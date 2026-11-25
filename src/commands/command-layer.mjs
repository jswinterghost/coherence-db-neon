// Thin command-layer entry point: all writes execute strictly through app_cmd.coherence_*
// via createAppCommands with a signed dbToken.
import { createAppCommands } from './app-cmd.mjs';

export function createCommandLayer({ pool, stores = null }) {
  return createAppCommands({ pool, stores });
}
