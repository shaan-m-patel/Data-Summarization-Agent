import { afterEach, describe, expect, it } from "vitest";

import { clearDatasets, saveDataset } from "../datasetStore";
import { resolveDatasetSelection } from "../datasetResolver";
import { normalizeHosts } from "../normalize";
import type { HostsDataset } from "../schema";

afterEach(() => {
  clearDatasets();
});

describe("resolveDatasetSelection", () => {
  it("returns the bundled sample when no dataset parameter is provided", async () => {
    const resolved = await resolveDatasetSelection(undefined);

    expect(resolved.datasetId).toBe("sample");
    expect(resolved.source).toBe("sample");
    expect(resolved.isFallback).toBe(false);
    expect(resolved.hosts.length).toBeGreaterThan(0);
  });

  it("falls back to the sample dataset when the id is unknown", async () => {
    const resolved = await resolveDatasetSelection("missing-id");

    expect(resolved.datasetId).toBe("sample");
    expect(resolved.source).toBe("sample");
    expect(resolved.isFallback).toBe(true);
    expect(resolved.notice).toMatch(/not found or has expired/i);
  });

  it("returns stored uploads with their metadata", async () => {
    const dataset: HostsDataset = {
      metadata: {
        description: "Resolver test dataset",
        created_at: new Date().toISOString(),
        data_sources: ["unit-test"],
        hosts_count: 1,
        ips_analyzed: ["203.0.113.10"],
      },
      hosts: [
        {
          ip: "203.0.113.10",
          location: {
            city: "Test City",
            country: "Test Country",
            country_code: "TC",
            coordinates: { latitude: 10, longitude: 20 },
          },
          autonomous_system: {
            asn: 12345,
            name: "Test Net",
            country_code: "TC",
          },
          services: [],
        },
      ],
    };

    const normalized = normalizeHosts(dataset);
    const id = saveDataset({
      dataset,
      normalized,
      source: "upload",
      label: "unit upload",
      ownerSessionId: "550e8400-e29b-41d4-a716-446655440000",
    });

    const resolved = await resolveDatasetSelection(id);

    expect(resolved.datasetId).toBe(id);
    expect(resolved.source).toBe("upload");
    expect(resolved.label).toBe("unit upload");
    expect(resolved.notice).toMatch(/15 minutes/i);
    expect(resolved.isFallback).toBe(false);
    expect(resolved.hosts).toEqual(normalized);
  });
});
