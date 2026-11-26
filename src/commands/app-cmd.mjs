// Single database-enforced write bridge: composes runtime, worker, and import commands
// executed strictly through app_cmd.coherence_* SECURITY DEFINER functions via withRequestTx.
import { createCommandTransport } from './cmd-transport.mjs';
import { createImportCommands } from './import-commands.mjs';
import { createRuntimeCommands } from './runtime-commands.mjs';
import { createWorkerCommands } from './worker-commands.mjs';

export function createAppCommands({ pool, stores = null }) {
  const transport = createCommandTransport({ pool });
  return {
    ...createImportCommands({ transport }),
    ...createRuntimeCommands({ transport, stores }),
    ...createWorkerCommands({ transport }),
  };
}
