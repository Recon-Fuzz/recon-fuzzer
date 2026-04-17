/**
 * Hook for lazy loading contract details
 */

import { useEffect } from 'react';
import { useFuzzerStore } from '@/stores/fuzzerStore';
import { useCommands } from './useFuzzerConnection';
import type { ContractInfo } from '@/types';

/**
 * Hook to get contract details with lazy loading
 * Returns the cached details if available, or undefined while loading
 */
export function useContractDetails(contractName: string | null): ContractInfo | undefined {
  // Subscribe directly to the cache entry to trigger re-renders when it changes
  const cached = useFuzzerStore((s) =>
    contractName ? s.contractDetails.get(contractName) : undefined
  );
  const cacheContractDetails = useFuzzerStore((s) => s.cacheContractDetails);
  const { getContractDetails } = useCommands();

  useEffect(() => {
    if (contractName && !cached) {
      // Fetch details if not cached
      getContractDetails(contractName).then((details) => {
        if (details) {
          cacheContractDetails(contractName, details);
        }
      });
    }
  }, [contractName, cached, getContractDetails, cacheContractDetails]);

  return cached;
}

/**
 * Hook to get source file content with lazy loading
 */
export function useSourceFileContent(path: string | null): string | undefined {
  // Subscribe directly to the cache entry to trigger re-renders when it changes
  const cached = useFuzzerStore((s) =>
    path ? s.sourceFileContents.get(path) : undefined
  );
  const cacheSourceFile = useFuzzerStore((s) => s.cacheSourceFile);
  const { getSourceFile } = useCommands();

  useEffect(() => {
    if (path && !cached) {
      // Fetch content if not cached
      getSourceFile(path).then((file) => {
        if (file) {
          cacheSourceFile(path, file);
        }
      });
    }
  }, [path, cached, getSourceFile, cacheSourceFile]);

  return cached?.content;
}
