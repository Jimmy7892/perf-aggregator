import { z } from "zod";

export const HourBucket = z.object({
  t: z.string(),
  // Prix optionnels pour ne pas exposer les entrées/sorties
  start_usd: z.number().optional(),
  end_usd: z.number().optional(),
  return_pct: z.number(),
  trades: z.number(),
  volume_base: z.number(),
  volume_quote: z.number(),
  fees_usd: z.number()
});

export const IngestPayload = z.object({
  client_id: z.string(),
  exchange: z.string(),
  connector_version: z.string(),
  period_start: z.string(),
  period_end: z.string(),
  hourly_buckets: z.array(HourBucket),
  totals: z.object({
    trades: z.number(),
    volume_base: z.number(),
    volume_quote: z.number(),
    fees_usd: z.number()
  }),
  metadata: z.record(z.any()).optional(),
  signature: z.string()
});

export type HourBucketT = z.infer<typeof HourBucket>;
export type IngestPayloadT = z.infer<typeof IngestPayload>;

