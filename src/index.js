export { runEngine, generateSbom, default } from './engine/index.js';
export { scanProject, scanProjectSync } from './scanner/index.js';
export {
  discoverFirstPartyComponents,
  discoverFirstPartyComponentsSync,
  discoverWorkspaces,
  discoverWorkspacesSync,
  classifyComponent,
  classifyComponents,
  isVersionCompatible,
} from './workspaceDiscovery.js';
