"use server";

import "server-only";

import { redirect } from "next/navigation";
import { ZodError } from "zod";

import { saveDataset } from "../datasetStore";
import { normalizeHosts } from "../normalize";
import { HostsDatasetSchema, type HostsDataset } from "../schema";
import { loadHostsDataset } from "../loader";
import { getOrCreateSession } from "../session";

import type { DatasetSelectionState } from "./types";

type FormMode = "sample" | "upload";
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

function formatZodIssues(error: ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.join(".");
    return path ? `${issue.message} at \`${path}\`` : issue.message;
  });
}

interface DetailedError extends Error {
  details?: string[];
}

function isDetailedError(error: unknown): error is DetailedError {
  return error instanceof Error && Array.isArray((error as DetailedError).details);
}

function createDetailedError(message: string, details?: string[]): DetailedError {
  const error = new Error(message) as DetailedError;
  error.details = details ?? [];
  return error;
}

function inferMode(formData: FormData): FormMode {
  const rawMode = formData.get("mode");
  return rawMode === "sample" ? "sample" : "upload";
}

async function handleSampleSelection(): Promise<never> {
  const dataset = await loadHostsDataset();
  const normalized = normalizeHosts(dataset);
  const session = await getOrCreateSession();
  const datasetId = saveDataset({
    dataset,
    normalized,
    source: "sample",
    label: "Bundled sample dataset",
    ownerSessionId: session.id,
  });
  redirect(`/hosts?dataset=${datasetId}`);
}

async function parseUploadedDataset(file: Blob): Promise<HostsDataset> {
  const rawText = await readDatasetFile(file);

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (error) {
    throw createDetailedError(
      `Uploaded file is not valid JSON. ${(error as Error).message}`,
    );
  }

  const result = HostsDatasetSchema.safeParse(parsed);
  if (!result.success) {
    const formatted = formatZodIssues(result.error).slice(0, 8);
    const message =
      "Dataset did not match the expected schema. Please review the structure.";
    const errorDetails = formatted.length > 0 ? formatted : undefined;

    throw createDetailedError(message, errorDetails);
  }

  return result.data;
}

export async function selectDatasetAction(
  _prevState: DatasetSelectionState,
  formData: FormData,
): Promise<DatasetSelectionState> {
  try {
    const mode = inferMode(formData);

    if (mode === "sample") {
      await handleSampleSelection();
      // The function above always redirects, this line should never be reached
      throw new Error("handleSampleSelection should have redirected");
    }

    const file = formData.get("dataset");
    if (!(file instanceof Blob)) {
      return {
        status: "error",
        message: "Please choose a JSON file that matches the Censys dataset schema.",
      };
    }

    if (file.size === 0) {
      return {
        status: "error",
        message: "The selected file is empty. Please upload a populated dataset.",
      };
    }

    if (file.size > MAX_UPLOAD_BYTES) {
      return {
        status: "error",
        message:
          "The dataset exceeds the 2MB upload limit. Please provide a smaller file.",
      };
    }

    const dataset = await parseUploadedDataset(file);
    const normalized = normalizeHosts(dataset);
    const fileName = readFileName(file);
    const session = await getOrCreateSession();

    const datasetId = saveDataset({
      dataset,
      normalized,
      source: "upload",
      label: fileName,
      ownerSessionId: session.id,
    });

    redirect(`/hosts?dataset=${datasetId}`);
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }
    if (isDetailedError(error)) {
      return {
        status: "error",
        message: error.message,
        details: error.details,
      };
    }

    console.error("[dataset-selection] Unexpected failure", error);
    return {
      status: "error",
      message:
        "We could not process that dataset. Please verify the contents and try again.",
    };
  }

  return {
    status: "idle",
  };
}

async function readDatasetFile(file: Blob): Promise<string> {
  const textFn = (file as { text?: () => Promise<string> }).text;
  if (typeof textFn === "function") {
    return await textFn.call(file);
  }

  const arrayBufferFn = (file as { arrayBuffer?: () => Promise<ArrayBuffer> })
    .arrayBuffer;
  if (typeof arrayBufferFn === "function") {
    const buffer = await arrayBufferFn.call(file);
    return Buffer.from(buffer).toString("utf-8");
  }

  return await new Response(file).text();
}

function readFileName(file: Blob): string | undefined {
  if (
    typeof file === "object" &&
    file !== null &&
    "name" in file &&
    typeof (file as { name?: unknown }).name === "string"
  ) {
    return (file as { name: string }).name;
  }
  return undefined;
}

function isRedirectError(error: unknown): error is Error & { digest: string } {
  if (!(error instanceof Error)) {
    return false;
  }
  const digest = (error as { digest?: unknown }).digest;
  return typeof digest === "string" && digest.startsWith("NEXT_REDIRECT");
}
