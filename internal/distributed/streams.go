package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"distributed-scanner/internal/model"

	"github.com/redis/go-redis/v9"
)

type StreamClient struct {
	rdb *redis.Client
}

func NewStreamClient(rdb *redis.Client) *StreamClient {
	return &StreamClient{rdb: rdb}
}

func (s *StreamClient) PublishEnvelope(ctx context.Context, stream string, env *MessageEnvelope) (string, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope failed: %w", err)
	}

	res, err := s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()
	return res, err
}

func (s *StreamClient) CreateGroup(ctx context.Context, stream, group string) error {
	err := s.rdb.XGroupCreateMkStream(ctx, stream, group, "$").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

func (s *StreamClient) Ack(ctx context.Context, stream, group, messageID string) error {
	return s.rdb.XAck(ctx, stream, group, messageID).Err()
}

// WriteScanResult 将单目标扫描统计写入中心结果池 (dast:results:{runID}) 与实时进度计数 (dast:status:{runID})
func (s *StreamClient) WriteScanResult(ctx context.Context, runID, target string, st model.ScanRunStats) error {
	runKey := fmt.Sprintf("dast:results:%s", runID)
	statusKey := fmt.Sprintf("dast:status:%s", runID)

	summary, err := json.Marshal(map[string]interface{}{
		"open_ports":      st.OpenPorts,
		"services_found":  st.ServicesFound,
		"endpoints_found": st.EndpointsFound,
		"findings_count":  st.FindingsCount,
		"duration_ms":     st.DurationMs,
	})
	if err != nil {
		return fmt.Errorf("marshal scan summary: %w", err)
	}

	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, runKey, target, string(summary))
	pipe.HIncrBy(ctx, statusKey, "scanned_targets", 1)
	pipe.HIncrBy(ctx, statusKey, "open_ports", int64(st.OpenPorts))
	pipe.HIncrBy(ctx, statusKey, "services_found", int64(st.ServicesFound))
	pipe.HIncrBy(ctx, statusKey, "endpoints_found", int64(st.EndpointsFound))
	pipe.HIncrBy(ctx, statusKey, "findings_count", int64(st.FindingsCount))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("write scan result: %w", err)
	}
	return nil
}

func (s *StreamClient) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]redis.XMessage, error) {
	streams, err := s.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{stream, ">"},
		Count:    count,
		Block:    block,
	}).Result()
	if err != nil {
		return nil, err
	}
	if len(streams) > 0 {
		return streams[0].Messages, nil
	}
	return nil, nil
}
