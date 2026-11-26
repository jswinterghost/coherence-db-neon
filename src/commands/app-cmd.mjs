// Single database-enforced write bridge: composes Coherence (runtime, worker, import) and IAM commands
// executed strictly through app_cmd.* SECURITY DEFINER functions via withRequestTx.
import { createCommandTransport } from './cmd-transport.mjs';
import { createIamCommands } from './iam-cmd.mjs';
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

export { createIamCommands };
