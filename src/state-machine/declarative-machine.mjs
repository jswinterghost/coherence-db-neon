// Reusable declarative state-machine library: declare states, transitions, guards, and database bindings
// once as data to drive static validation, PostgreSQL catalog checks, and Markdown docs.
import { canonicalJson, sha256Hex } from '../util/crypto.mjs';

export class StateMachineDefinitionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateMachineDefinitionError';
  }
}

function deepFreeze(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const val of Object.values(obj)) {
    if (val && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

function stripFunctions(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'function') return undefined;
  if (Array.isArray(value)) return value.map(stripFunctions).filter((v) => v !== undefined);
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === 'function') continue;
      out[k] = stripFunctions(v);
    }
    return out;
  }
  return value;
}

function mdEscape(text) {
  return String(text ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function mermaidId(stateId) {
  return String(stateId).replace(/[^A-Za-z0-9_]/g, '_');
}

export function defineStateMachine(rawSpec) {
  if (!rawSpec || typeof rawSpec !== 'object') {
    throw new StateMachineDefinitionError('State machine spec must be an object.');
  }
  const {
    id,
    title,
    version = '1.0.0',
    requirementRef = '',
    description = '',
    derived = false,
    states = [],
    guards = {},
    transitions = [],
    dbChecks = [],
  } = rawSpec;

  if (!id || typeof id !== 'string') throw new StateMachineDefinitionError('Machine id is required.');
  if (!title || typeof title !== 'string') throw new StateMachineDefinitionError(`Machine ${id}: title is required.`);
  if (!Array.isArray(states) || states.length === 0) {
    throw new StateMachineDefinitionError(`Machine ${id}: states must be a non-empty array.`);
  }
  if (!Array.isArray(transitions) || transitions.length === 0) {
    throw new StateMachineDefinitionError(`Machine ${id}: transitions must be a non-empty array.`);
  }

  const stateMap = new Map();
  for (const st of states) {
    if (!st?.id || typeof st.id !== 'string') {
      throw new StateMachineDefinitionError(`Machine ${id}: every state must have a string id.`);
    }
    if (stateMap.has(st.id)) {
      throw new StateMachineDefinitionError(`Machine ${id}: duplicate state id '${st.id}'.`);
    }
    stateMap.set(st.id, {
      id: st.id,
      label: st.label || st.id,
      initial: Boolean(st.initial),
      terminal: Boolean(st.terminal),
      pseudo: Boolean(st.pseudo),
      description: st.description || '',
      derivationRule: st.derivationRule || null,
    });
  }

  const initialStates = [...stateMap.values()].filter((s) => s.initial).map((s) => s.id);
  if (initialStates.length === 0) {
    throw new StateMachineDefinitionError(`Machine ${id}: at least one state must be marked initial: true.`);
  }

  const guardMap = new Map();
  for (const [key, g] of Object.entries(guards)) {
    const gId = g.id || key;
    if (guardMap.has(gId)) {
      throw new StateMachineDefinitionError(`Machine ${id}: duplicate guard id '${gId}'.`);
    }
    guardMap.set(gId, {
      id: gId,
      description: g.description || '',
      requirementRef: g.requirementRef || '',
      dbEnforcement: g.dbEnforcement || null,
      evaluate: typeof g.evaluate === 'function' ? g.evaluate : null,
    });
  }

  const transitionMap = new Map();
  const outgoing = new Map([...stateMap.keys()].map((s) => [s, []]));

  for (const tr of transitions) {
    if (!tr?.id || typeof tr.id !== 'string') {
      throw new StateMachineDefinitionError(`Machine ${id}: every transition must have a string id.`);
    }
    if (transitionMap.has(tr.id)) {
      throw new StateMachineDefinitionError(`Machine ${id}: duplicate transition id '${tr.id}'.`);
    }
    const fromList = Array.isArray(tr.from) ? tr.from : [tr.from];
    if (fromList.length === 0) {
      throw new StateMachineDefinitionError(`Machine ${id}: transition '${tr.id}' must declare at least one 'from' state.`);
    }
    for (const f of fromList) {
      if (!stateMap.has(f)) {
        throw new StateMachineDefinitionError(`Machine ${id}: transition '${tr.id}' references unknown from state '${f}'.`);
      }
      if (stateMap.get(f).terminal && !tr.allowFromTerminal) {
        throw new StateMachineDefinitionError(`Machine ${id}: transition '${tr.id}' leaves terminal state '${f}'.`);
      }
    }
    if (!stateMap.has(tr.to)) {
      throw new StateMachineDefinitionError(`Machine ${id}: transition '${tr.id}' references unknown to state '${tr.to}'.`);
    }
    const trGuards = Array.isArray(tr.guards) ? tr.guards : [];
    for (const gId of trGuards) {
      if (!guardMap.has(gId)) {
        throw new StateMachineDefinitionError(`Machine ${id}: transition '${tr.id}' references unknown guard '${gId}'.`);
      }
    }
    const normalized = {
      id: tr.id,
      action: tr.action || tr.id,
      actorKinds: Array.isArray(tr.actorKinds) ? [...tr.actorKinds] : [],
      from: [...fromList],
      to: tr.to,
      guards: [...trGuards],
      effects: Array.isArray(tr.effects) ? [...tr.effects] : [],
      requirementRef: tr.requirementRef || '',
      dbEnforcement: tr.dbEnforcement || null,
    };
    transitionMap.set(tr.id, normalized);
    for (const f of fromList) outgoing.get(f).push(normalized);
  }

  const visited = new Set(initialStates);
  const queue = [...initialStates];
  while (queue.length > 0) {
    const cur = queue.shift();
    for (const tr of outgoing.get(cur) || []) {
      if (!visited.has(tr.to)) {
        visited.add(tr.to);
        queue.push(tr.to);
      }
    }
  }
  const unreachable = [...stateMap.keys()].filter((s) => !visited.has(s));
  if (unreachable.length > 0) {
    throw new StateMachineDefinitionError(
      `Machine ${id}: unreachable state(s) declared: ${unreachable.join(', ')}`,
    );
  }

  const deadEnds = [...stateMap.values()]
    .filter((s) => !s.terminal && (outgoing.get(s.id) || []).length === 0)
    .map((s) => s.id);
  if (deadEnds.length > 0) {
    throw new StateMachineDefinitionError(
      `Machine ${id}: non-terminal dead-end state(s) with no outgoing transition: ${deadEnds.join(', ')}`,
    );
  }

  const normalizedSpec = deepFreeze({
    id,
    title,
    version,
    requirementRef,
    description,
    derived: Boolean(derived),
    states: [...stateMap.values()],
    guards: Object.fromEntries([...guardMap.entries()]),
    transitions: [...transitionMap.values()],
    dbChecks: Array.isArray(dbChecks) ? dbChecks : [],
  });

  const specSha256 = sha256Hex(canonicalJson(stripFunctions(normalizedSpec)));

  function evaluateTransition(transitionId, currentState, context = {}) {
    const tr = transitionMap.get(transitionId);
    if (!tr) throw new Error(`Unknown transition '${transitionId}' in machine '${id}'.`);
    if (!tr.from.includes(currentState)) {
      return {
        ok: false,
        transitionId,
        from: currentState,
        to: tr.to,
        reason: `Transition '${transitionId}' is not allowed from state '${currentState}'.`,
        failedGuards: [],
      };
    }
    const failedGuards = [];
    for (const gId of tr.guards) {
      const guard = guardMap.get(gId);
      if (guard.evaluate && !guard.evaluate(context)) {
        failedGuards.push({ id: gId, description: guard.description });
      }
    }
    return {
      ok: failedGuards.length === 0,
      transitionId,
      from: currentState,
      to: tr.to,
      reason: failedGuards.length === 0 ? null : `Guard(s) failed: ${failedGuards.map((g) => g.id).join(', ')}`,
      failedGuards,
    };
  }

  function allowedTransitionsFrom(currentState, context = null) {
    const list = outgoing.get(currentState) || [];
    if (!context) return list.map((tr) => tr.id);
    return list.filter((tr) => evaluateTransition(tr.id, currentState, context).ok).map((tr) => tr.id);
  }

  function verifyGraph() {
    return {
      ok: unreachable.length === 0 && deadEnds.length === 0,
      unreachable,
      deadEnds,
      stateCount: stateMap.size,
      nonPseudoStateCount: [...stateMap.values()].filter((s) => !s.pseudo).length,
      transitionCount: transitionMap.size,
      guardCount: guardMap.size,
    };
  }

  async function verifyAgainstPostgres(pool) {
    const problems = [];
    const checked = { tables: 0, triggers: 0, functions: 0, indexes: 0, constraints: 0, derivedFunctions: 0 };

    const requiredTables = new Set();
    const requiredTriggers = new Set(); // "schema.table::trigger"
    const requiredFunctions = new Set(); // "schema.fn"
    const requiredIndexes = new Set(); // "schema.index"

    const collectEnforcement = (enf) => {
      if (!enf) return;
      if (enf.table) requiredTables.add(enf.table);
      for (const t of enf.tables || []) requiredTables.add(t);
      if (enf.trigger && enf.table) requiredTriggers.add(`${enf.table}::${enf.trigger}`);
      for (const t of enf.triggers || []) {
        if (t.includes('::')) requiredTriggers.add(t);
        else if (enf.table) requiredTriggers.add(`${enf.table}::${t}`);
      }
      if (enf.function) requiredFunctions.add(enf.function);
      for (const f of enf.functions || []) requiredFunctions.add(f);
      for (const idx of enf.indexes || []) requiredIndexes.add(idx);
    };

    for (const g of guardMap.values()) collectEnforcement(g.dbEnforcement);
    for (const tr of transitionMap.values()) collectEnforcement(tr.dbEnforcement);

    for (const qualifiedTable of requiredTables) {
      const [schema, table] = qualifiedTable.split('.');
      const res = await pool.query(
        `SELECT 1 FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p')`,
        [schema, table],
      );
      checked.tables += 1;
      if (res.rows.length === 0) problems.push(`Missing declared table: ${qualifiedTable}`);
    }

    for (const specKey of requiredTriggers) {
      const [qualifiedTable, triggerName] = specKey.split('::');
      const [schema, table] = qualifiedTable.split('.');
      const res = await pool.query(
        `SELECT t.tgenabled
         FROM pg_catalog.pg_trigger t
         JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = $1 AND c.relname = $2 AND t.tgname = $3 AND NOT t.tgisinternal`,
        [schema, table, triggerName],
      );
      checked.triggers += 1;
      if (res.rows.length === 0) {
        problems.push(`Missing declared trigger: ${triggerName} on ${qualifiedTable}`);
      } else if (res.rows[0].tgenabled === 'D') {
        problems.push(`Declared trigger is disabled: ${triggerName} on ${qualifiedTable}`);
      }
    }

    for (const qualifiedFn of requiredFunctions) {
      const [schema, fnName] = qualifiedFn.split('.');
      const res = await pool.query(
        `SELECT p.proconfig
         FROM pg_catalog.pg_proc p
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = $1 AND p.proname = $2`,
        [schema, fnName],
      );
      checked.functions += 1;
      if (res.rows.length === 0) {
        problems.push(`Missing declared function: ${qualifiedFn}`);
      }
    }

    for (const qualifiedIdx of requiredIndexes) {
      const [schema, idxName] = qualifiedIdx.split('.');
      const res = await pool.query(
        `SELECT 1 FROM pg_catalog.pg_indexes WHERE schemaname = $1 AND indexname = $2`,
        [schema, idxName],
      );
      checked.indexes += 1;
      if (res.rows.length === 0) problems.push(`Missing declared index: ${qualifiedIdx}`);
    }

    for (const check of normalizedSpec.dbChecks) {
      if (check.kind === 'column_check_values') {
        const [schema, table] = check.table.split('.');
        const res = await pool.query(
          `SELECT pg_catalog.pg_get_constraintdef(con.oid) AS def
           FROM pg_catalog.pg_constraint con
           JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = $1 AND c.relname = $2 AND con.contype = 'c'`,
          [schema, table],
        );
        checked.constraints += 1;
        const matching = res.rows
          .map((r) => r.def)
          .find((def) => def.includes(check.column) && def.includes('ARRAY['));
        if (!matching) {
          problems.push(`Missing CHECK constraint on ${check.table}.${check.column}`);
        } else {
          const actualValues = [...matching.matchAll(/'([^']+)'::text/g)].map((m) => m[1]).sort();
          const expectedValues = [...check.expectedValues].sort();
          if (JSON.stringify(actualValues) !== JSON.stringify(expectedValues)) {
            problems.push(
              `CHECK constraint mismatch on ${check.table}.${check.column}: DB has [${actualValues.join(', ')}], machine declares [${expectedValues.join(', ')}]`,
            );
          }
        }
      } else if (check.kind === 'derived_stage_literals') {
        const [schema, fnName] = check.function.split('.');
        const res = await pool.query(
          `SELECT pg_catalog.pg_get_functiondef(p.oid) AS def
           FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = $1 AND p.proname = $2`,
          [schema, fnName],
        );
        checked.derivedFunctions += 1;
        if (res.rows.length === 0) {
          problems.push(`Missing derived stage function: ${check.function}`);
        } else {
          const def = res.rows[0].def;
          const literalReturns = new Set([...def.matchAll(/RETURN\s+'([^']+)'/gi)].map((m) => m[1]));
          const expectedStages = [...stateMap.values()].filter((s) => !s.pseudo).map((s) => s.id).sort();
          const actualStages = [...literalReturns].sort();
          if (JSON.stringify(actualStages) !== JSON.stringify(expectedStages)) {
            problems.push(
              `Derived stage mismatch in ${check.function}: SQL emits [${actualStages.join(', ')}], machine declares [${expectedStages.join(', ')}]`,
            );
          }
        }
      }
    }

    return { passed: problems.length === 0, machineId: id, checked, problems };
  }

  function renderMarkdown() {
    const lines = [];
    lines.push(`## ${title} (\`${id}\`)`);
    lines.push('');
    if (description) {
      lines.push(description);
      lines.push('');
    }
    const meta = [
      `Version: \`${version}\``,
      derived ? 'Storage: derived (never stored)' : 'Storage: event-sourced lifecycle',
      requirementRef ? `Requirements: ${requirementRef}` : null,
      `Spec SHA-256: \`${specSha256.slice(0, 16)}\``,
    ].filter(Boolean);
    lines.push(`- ${meta.join(' | ')}`);
    lines.push('');

    lines.push('### States');
    lines.push('');
    lines.push('| State | Kind | Description | Derivation / Rule |');
    lines.push('|---|---|---|---|');
    for (const st of normalizedSpec.states) {
      const kind = st.pseudo
        ? 'entry (pseudo)'
        : st.terminal
          ? 'terminal'
          : st.initial
            ? 'initial'
            : 'active';
      lines.push(`| \`${mdEscape(st.id)}\` | ${kind} | ${mdEscape(st.description)} | ${mdEscape(st.derivationRule || '-')} |`);
    }
    lines.push('');

    lines.push('### Transitions');
    lines.push('');
    lines.push('| Transition | Action | From | To | Actors | Guards | Effects |');
    lines.push('|---|---|---|---|---|---|---|');
    for (const tr of normalizedSpec.transitions) {
      const fromStr = tr.from.map((s) => `\`${mdEscape(s)}\``).join(', ');
      const actorsStr = tr.actorKinds.length ? tr.actorKinds.map((a) => `\`${a}\``).join(', ') : '-';
      const guardsStr = tr.guards.length ? tr.guards.map((g) => `\`${g}\``).join(', ') : '-';
      const effectsStr = tr.effects.length ? tr.effects.map(mdEscape).join('; ') : '-';
      lines.push(`| \`${mdEscape(tr.id)}\` | ${mdEscape(tr.action)} | ${fromStr} | \`${mdEscape(tr.to)}\` | ${actorsStr} | ${guardsStr} | ${effectsStr} |`);
    }
    lines.push('');

    lines.push('### Guards and Database Enforcement');
    lines.push('');
    const hasGuardReqs = Object.values(normalizedSpec.guards).some((g) => Boolean(g.requirementRef));
    if (hasGuardReqs) {
      lines.push('| Guard | Requirement | Rule | Database Enforcement |');
      lines.push('|---|---|---|---|');
    } else {
      lines.push('| Guard | Rule | Database Enforcement |');
      lines.push('|---|---|---|');
    }
    for (const g of Object.values(normalizedSpec.guards)) {
      const enfParts = [];
      if (g.dbEnforcement?.table) enfParts.push(`table \`${g.dbEnforcement.table}\``);
      if (g.dbEnforcement?.trigger) enfParts.push(`trigger \`${g.dbEnforcement.trigger}\``);
      if (g.dbEnforcement?.triggers?.length) {
        enfParts.push(`triggers ${g.dbEnforcement.triggers.map((t) => `\`${t}\``).join(', ')}`);
      }
      if (g.dbEnforcement?.indexes?.length) {
        enfParts.push(`indexes ${g.dbEnforcement.indexes.map((i) => `\`${i}\``).join(', ')}`);
      }
      if (hasGuardReqs) {
        lines.push(`| \`${mdEscape(g.id)}\` | ${mdEscape(g.requirementRef || '-')} | ${mdEscape(g.description)} | ${enfParts.join('; ') || '-'} |`);
      } else {
        lines.push(`| \`${mdEscape(g.id)}\` | ${mdEscape(g.description)} | ${enfParts.join('; ') || '-'} |`);
      }
    }
    lines.push('');

    lines.push('### State Diagram');
    lines.push('');
    lines.push('```mermaid');
    lines.push('stateDiagram-v2');
    for (const st of normalizedSpec.states) {
      const mid = mermaidId(st.id);
      if (!st.pseudo && mid !== st.id) {
        lines.push(`  state "${st.label}" as ${mid}`);
      }
      if (st.initial && !st.pseudo) {
        lines.push(`  [*] --> ${mid}`);
      }
    }
    for (const tr of normalizedSpec.transitions) {
      for (const f of tr.from) {
        const fromNode = stateMap.get(f).pseudo ? '[*]' : mermaidId(f);
        lines.push(`  ${fromNode} --> ${mermaidId(tr.to)}: ${tr.action}`);
      }
    }
    for (const st of normalizedSpec.states) {
      if (st.terminal) {
        lines.push(`  ${mermaidId(st.id)} --> [*]`);
      }
    }
    lines.push('```');
    lines.push('');
    return lines.join('\n');
  }

  return Object.freeze({
    id,
    title,
    version,
    spec: normalizedSpec,
    specSha256,
    stateIds: Object.freeze([...stateMap.keys()]),
    nonPseudoStateIds: Object.freeze([...stateMap.values()].filter((s) => !s.pseudo).map((s) => s.id)),
    initialStates: Object.freeze(initialStates),
    terminalStates: Object.freeze([...stateMap.values()].filter((s) => s.terminal).map((s) => s.id)),
    evaluateTransition,
    allowedTransitionsFrom,
    reachableStates: () => new Set(visited),
    verifyGraph,
    verifyAgainstPostgres,
    renderMarkdown,
  });
}

export function renderMachinesDocument({
  title,
  intro = '',
  sourceModule = '',
  machines = [],
}) {
  const combinedHash = sha256Hex(canonicalJson(machines.map((m) => ({ id: m.id, specSha256: m.specSha256 }))));
  const lines = [
    `<!-- GENERATED FILE: DO NOT EDIT BY HAND. -->`,
    `<!-- Source: ${sourceModule || 'declarative state machine spec'} | Checksum: ${combinedHash} -->`,
    '',
    `# ${title}`,
    '',
  ];
  if (intro) {
    lines.push(intro);
    lines.push('');
  }
  lines.push('| Machine | ID | States | Transitions | Guards | Spec SHA-256 |');
  lines.push('|---|---|---|---|---|---|');
  for (const m of machines) {
    const g = m.verifyGraph();
    lines.push(`| ${mdEscape(m.title)} | \`${m.id}\` | ${g.nonPseudoStateCount} | ${g.transitionCount} | ${g.guardCount} | \`${m.specSha256.slice(0, 16)}\` |`);
  }
  lines.push('');
  for (const m of machines) {
    lines.push('---');
    lines.push('');
    lines.push(m.renderMarkdown());
  }
  return `${lines.join('\n').trimEnd()}\n`;
}
