export { runEngine, generateSbom, default } from './engine/index.js';
export { scanProject } from './scanner/index.js';
export {
  discoverFirstPartyComponents,
  discoverFirstPartyComponentsSync,
  discoverWorkspaces,
  discoverWorkspacesSync,
  classifyComponent,
  classifyComponents,
  isVersionCompatible,
} from './workspaceDiscovery.js';
