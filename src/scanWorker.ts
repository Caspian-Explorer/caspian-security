/**
 * Worker-thread entry point for parallel workspace scans.
 *
 * The main thread (runWorkspaceScanParallel in scanRunner.ts) hands each
 * worker a slice of file paths; the worker reads, filters, and scans them
 * with the shared `scanFile` engine and posts back FileResults. Rules are
 * loaded fresh inside the worker (regexes/functions can't cross the thread
 * boundary), which is cheap — just module evaluation.
 */

import { parentPort, workerData } from 'worker_threads';
import { scanFileList, FileResult } from './scanRunner';

export interface ScanWorkerData {
  files: string[];
  workspace: string;
  maxFileSize: number;
  runTaint: boolean;
}

export interface ScanWorkerResult {
  results: FileResult[];
  filesSkipped: number;
}

export function scanFileBatch(data: ScanWorkerData): ScanWorkerResult {
  return scanFileList(data.files, data.workspace, data.maxFileSize, data.runTaint);
}

// When spawned as a worker, do the work and post it back.
if (parentPort && workerData) {
  const result = scanFileBatch(workerData as ScanWorkerData);
  parentPort.postMessage(result);
}
