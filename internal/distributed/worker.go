// Package distributed provides Redis Streams multi-tiered distributed task queue orchestration and worker runtimes.
package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"distributed-scanner/internal/engine"
	"distributed-scanner/internal/model"

	"github.com/redis/go-redis/v9"
)

// 扫描完成日志前缀，供集群监控/benchmark 统计
const scanDoneLog = "[scan-done]"

const (
	DefaultRawStream    = "dast.command.raw"
	DefaultTargetStream = "dast.command.network"
	DefaultGroup        = "worker.group.1"
)

type WorkerRuntime struct {
	client       *StreamClient
	rawStream    string
	targetStream string
	group        string
	consumerID   string
	runner       *engine.Runner
}

func NewWorkerRuntime(rdb *redis.Client, rawStream, targetStream, group string, runner *engine.Runner) *WorkerRuntime {
	if rawStream == "" {
		rawStream = DefaultRawStream
	}
	if targetStream == "" {
		targetStream = DefaultTargetStream
	}
	if group == "" {
		group = DefaultGroup
	}

	return &WorkerRuntime{
		client:       NewStreamClient(rdb),
		rawStream:    rawStream,
		targetStream: targetStream,
		group:        group,
		consumerID:   fmt.Sprintf("worker-%s", model.NewUUID()[:8]),
		runner:       runner,
	}
}

// Run launches concurrent worker loops for both raw ingestion/expansion and scanning execution.
func (w *WorkerRuntime) Run(ctx context.Context) error {
	_ = w.client.CreateGroup(ctx, w.rawStream, w.group)
	_ = w.client.CreateGroup(ctx, w.targetStream, w.group)

	var wg sync.WaitGroup

	// Loop 1: Ingestion & Distributed Target Parser (dast.command.raw -> dast.command.network)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runParserLoop(ctx)
	}()

	// Loop 2: Network Scan Execution (dast.command.network -> 5-stage pipeline)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runScanLoop(ctx)
	}()

	wg.Wait()
	return nil
}

// runParserLoop consumes raw target tasks from rawStream, expands CIDR/domains, and publishes to targetStream.
func (w *WorkerRuntime) runParserLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := w.client.ReadGroup(ctx, w.rawStream, w.group, w.consumerID, 1, 2*time.Second)
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, msg := range msgs {
			rawJSON, ok := msg.Values["data"].(string)
			if !ok {
				_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
				continue
			}

			var env MessageEnvelope
			if err := json.Unmarshal([]byte(rawJSON), &env); err != nil {
				_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
				continue
			}

			var rawInput RawTaskInput
			if err := json.Unmarshal(env.Payload, &rawInput); err == nil {
				// Expand CIDRs and Domains concurrently
				expanded := model.ExpandTargets(rawInput.RawTargets)

				for _, tgt := range expanded {
					if !tgt.IsValid {
						continue
					}

					// Domain DNS Lookup
					if tgt.Kind == model.TargetKindDomain {
						if ips, err := net.LookupIP(tgt.Host); err == nil && len(ips) > 0 {
							tgt.Host = ips[0].String()
						}
					}

					stageInput := StageInput{
						ScanRunID:  rawInput.ScanRunID,
						StageRunID: model.NewUUID(),
						StageName:  "network_scan",
						Target:     tgt.CanonicalTarget,
						Port:       tgt.Port,
						PortRange:  rawInput.PortRange,
						ScanPolicy: rawInput.ScanPolicy,
						RateLimit:  rawInput.RateLimit,
						Budget:     rawInput.Budget,
					}

					idempotencyKey := fmt.Sprintf("%s:%s", rawInput.ScanRunID, tgt.CanonicalTarget)
					if outEnv, err := NewEnvelope(idempotencyKey, "StageInput", stageInput, 3); err == nil {
						_, _ = w.client.PublishEnvelope(ctx, w.targetStream, outEnv)
					}
				}
			}

			_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
		}
	}
}

// runScanLoop consumes single normalized targets from targetStream and executes the 5-stage pipeline.
func (w *WorkerRuntime) runScanLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := w.client.ReadGroup(ctx, w.targetStream, w.group, w.consumerID, 1, 2*time.Second)
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, msg := range msgs {
			rawJSON, ok := msg.Values["data"].(string)
			if !ok {
				_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
				continue
			}

			var env MessageEnvelope
			if err := json.Unmarshal([]byte(rawJSON), &env); err != nil {
				_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
				continue
			}

			var input StageInput
			if err := json.Unmarshal(env.Payload, &input); err == nil {
				// Execute 5-stage scanning in-process on this worker node
				res, runErr := w.runner.Run(ctx, engine.ScanOptions{
					Targets:      []string{input.Target},
					PortOverride: input.PortRange,
					Profile:      "fast",
				})
				if runErr != nil {
					fmt.Printf("[worker %s] 扫描失败 %s: %v\n", w.consumerID, input.Target, runErr)
				} else if res != nil {
					// 上报统计到中心结果池，供控制端聚合与实时进度追踪
					if err := w.client.WriteScanResult(ctx, input.ScanRunID, input.Target, res.Stats); err != nil {
						fmt.Printf("[worker %s] 上报结果失败 %s: %v\n", w.consumerID, input.Target, err)
					}
					fmt.Printf("%s worker=%s run=%s target=%s findings=%d ports=%d services=%d duration_ms=%d\n",
						scanDoneLog, w.consumerID, input.ScanRunID, input.Target,
						res.Stats.FindingsCount, res.Stats.OpenPorts, res.Stats.ServicesFound, res.Stats.DurationMs)
				}
			}

			_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
		}
	}
}
