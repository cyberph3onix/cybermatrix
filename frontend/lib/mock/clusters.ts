import type { Cluster } from "../types";

// Mock data for GET /clusters. Domains use reserved/.invalid-style names only.
export const MOCK_CLUSTERS: Cluster[] = [
  {
    cluster_id: "cl-7a21",
    label: "SBI net-banking lookalikes on one host",
    first_seen: "2026-11-05T09:12:00Z",
    last_seen: "2026-11-08T02:00:00Z",
    top_classification: "confirmed_malicious",
    report_ids: [
      "5f0c2a8e-6b1d-4c43-9a0e-2f3b7d9c1a11",
      "a81d3f20-4e55-4b0a-8d1c-91b6c0e7f2a4",
      "0c9e17b3-72aa-4f6e-b5d8-3e1a47c2d905",
    ],
    shared_indicators: [
      { type: "ip", value: "203.0.113.7", report_count: 3 },
      { type: "nameserver", value: "ns1.example-dns.invalid", report_count: 3 },
      { type: "cert_sha256", value: "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f", report_count: 2 },
    ],
    member_domains: [
      "sbi.co.in.kyc-verify-now.top",
      "sbi-kyc-update.example",
      "netbanking-sbi.example",
    ],
  },
  {
    cluster_id: "cl-33f0",
    label: "Parcel-fee SMS campaign sharing a UPI ID",
    first_seen: "2026-11-02T14:40:00Z",
    last_seen: "2026-11-07T18:05:00Z",
    top_classification: "high_risk",
    report_ids: [
      "d2b5e6c1-90f3-4d27-a1e4-5c8f0b7a3e16",
      "6e4a8c92-1b3d-47f5-9a60-d7c2e8f1b543",
    ],
    shared_indicators: [
      { type: "upi_id", value: "pay.parcel@exampleupi", report_count: 2 },
      { type: "phone", value: "+91 90000 00000", report_count: 2 },
    ],
    member_domains: ["parcel-redelivery.example", "track-your-parcel.example"],
  },
];
