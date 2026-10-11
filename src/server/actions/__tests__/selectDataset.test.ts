import { afterEach, describe, expect, it, vi } from "vitest";

import { clearDatasets } from "../../datasetStore";
import { clearSessions } from "../../session";
import { selectDatasetAction } from "../selectDataset";
import { initialDatasetSelectionState } from "../types";

const redirectMock = vi.fn();

class MemoryFile extends Blob implements File {
  readonly lastModified: number;
  readonly name: string;
  readonly webkitRelativePath = "";
  private readonly rawText: string;

  constructor(bits: BlobPart[], fileName: string, options?: FilePropertyBag) {
    super(bits, options);
    this.name = fileName;
    this.lastModified = options?.lastModified ?? Date.now();
    this.rawText = bits.map((part) => toStringPart(part)).join("");
  }

  async text(): Promise<string> {
    return this.rawText;
  }

  override async arrayBuffer(): Promise<ArrayBuffer> {
    return new TextEncoder().encode(this.rawText).buffer;
  }
}

class MockFormData {
  private readonly store = new Map<string, FormDataEntryValue>();

  set(key: string, value: FormDataEntryValue) {
    this.store.set(key, value);
  }

  get(key: string): FormDataEntryValue | null {
    return this.store.has(key) ? this.store.get(key)! : null;
  }
}

function toFormData(mock: MockFormData): FormData {
  return mock as unknown as FormData;
}

function toStringPart(part: BlobPart): string {
  if (typeof part === "string") {
    return part;
  }
  if (part instanceof ArrayBuffer) {
    return new TextDecoder().decode(part);
  }
  if (ArrayBuffer.isView(part)) {
    const view = part as ArrayBufferView;
    const uint8 = new Uint8Array(
      view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength),
    );
    return new TextDecoder().decode(uint8);
  }
  if (part instanceof Blob) {
    throw new Error("Nested Blob parts are not supported in MemoryFile tests.");
  }
  return String(part);
}

vi.mock("server-only", () => ({}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get(name: string) {
      const value = cookieJar.get(name);
      return value ? { name, value } : undefined;
    },
    set(name: string, value: string) {
      cookieJar.set(name, value);
    },
  }),
}));

const cookieJar = new Map<string, string>();

vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    redirectMock(url);
    const error = new Error(`REDIRECT:${url}`);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test helper
    (error as any).digest = "NEXT_REDIRECT";
    throw error;
  },
}));

function buildValidDataset() {
  return {
    metadata: {
      description: "Test dataset",
      created_at: new Date().toISOString(),
      data_sources: ["unit-test"],
      hosts_count: 1,
      ips_analyzed: ["1.1.1.1"],
    },
    hosts: [
      {
        ip: "1.1.1.1",
        location: {
          city: "City",
          country: "Country",
          country_code: "TC",
          coordinates: { latitude: 0, longitude: 0 },
        },
        autonomous_system: {
          asn: 64512,
          name: "Test AS",
          country_code: "TC",
        },
        services: [],
      },
    ],
  };
}

afterEach(() => {
  redirectMock.mockReset();
  clearDatasets();
  clearSessions();
  cookieJar.clear();
});

describe("selectDatasetAction", () => {
  it("returns an error state when no file is provided", async () => {
    const form = new MockFormData();
    form.set("mode", "upload");

    const result = await selectDatasetAction(
      initialDatasetSelectionState,
      toFormData(form),
    );
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/choose a JSON file/i);
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("returns an error when the upload is not valid JSON", async () => {
    const form = new MockFormData();
    form.set("mode", "upload");
    form.set(
      "dataset",
      new MemoryFile(["{not-json"], "invalid.json", {
        type: "application/json",
      }),
    );

    const result = await selectDatasetAction(
      initialDatasetSelectionState,
      toFormData(form),
    );
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/not valid JSON/i);
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("limits uploads larger than 2MB", async () => {
    const form = new MockFormData();
    form.set("mode", "upload");
    const largeBuffer = new Uint8Array(2 * 1024 * 1024 + 1);
    form.set(
      "dataset",
      new MemoryFile([largeBuffer], "large.json", {
        type: "application/json",
      }),
    );

    const result = await selectDatasetAction(
      initialDatasetSelectionState,
      toFormData(form),
    );
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/exceeds the 2MB upload limit/i);
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("stores the sample dataset for the session and redirects with its id", async () => {
    const form = new MockFormData();
    form.set("mode", "sample");

    await expect(
      selectDatasetAction(initialDatasetSelectionState, toFormData(form)),
    ).rejects.toThrow(/REDIRECT:\/hosts\?dataset=[0-9a-f-]{36}/i);
    expect(redirectMock).toHaveBeenCalledTimes(1);
    expect(redirectMock.mock.calls[0][0]).toMatch(/\/hosts\?dataset=[0-9a-f-]{36}/i);
    expect(redirectMock.mock.calls[0][0]).not.toContain("dataset=sample");
  });

  it("stores valid uploads and redirects with a generated dataset id", async () => {
    const dataset = buildValidDataset();
    const form = new MockFormData();
    form.set("mode", "upload");
    form.set(
      "dataset",
      new MemoryFile([JSON.stringify(dataset)], "dataset.json", {
        type: "application/json",
      }),
    );

    await expect(
      selectDatasetAction(initialDatasetSelectionState, toFormData(form)),
    ).rejects.toThrow(/REDIRECT:\/hosts\?dataset=/);
    expect(redirectMock).toHaveBeenCalledTimes(1);
    expect(redirectMock.mock.calls[0][0]).toMatch(/\/hosts\?dataset=[\w-]+/);
  });
});
