import {
  APIGatewayNode,
  ContainerNode,
  DataStoreNode,
  ExternalEntityNode,
  HumanActorNode,
  IAMRoleNode,
  ManagedServiceNode,
  ProcessNode,
  ServerlessNode,
} from "./DFDNodeTypes";

export const nodeTypes = {
  process: ProcessNode,
  data_store: DataStoreNode,
  external_entity: ExternalEntityNode,
  human_actor: HumanActorNode,
  iam_role: IAMRoleNode,
  managed_service: ManagedServiceNode,
  api_gateway: APIGatewayNode,
  container: ContainerNode,
  serverless: ServerlessNode,
} as const;
