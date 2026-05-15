import {
  CircleUserRound,
  Cloud,
  Container,
  Database,
  KeyRound,
  Network,
  Shield,
  SquareArrowOutUpRight,
  Workflow,
  Zap,
  type LucideIcon,
  type LucideProps,
} from "lucide-react";

export type DFDIconProps = Omit<LucideProps, "ref">;
export type DFDIconComponent = (props: DFDIconProps) => JSX.Element;

function createDFDIcon(Icon: LucideIcon): DFDIconComponent {
  return function DFDIcon({
    size = 18,
    strokeWidth = 2,
    absoluteStrokeWidth = true,
    ...props
  }: DFDIconProps) {
    return (
      <Icon
        size={size}
        strokeWidth={strokeWidth}
        absoluteStrokeWidth={absoluteStrokeWidth}
        {...props}
      />
    );
  };
}

export const ProcessIcon = createDFDIcon(Workflow);
export const DataStoreIcon = createDFDIcon(Database);
export const ExternalEntityIcon = createDFDIcon(SquareArrowOutUpRight);
export const HumanActorIcon = createDFDIcon(CircleUserRound);
export const TrustBoundaryIcon = createDFDIcon(Shield);
export const APIGatewayIcon = createDFDIcon(Network);
export const ContainerIcon = createDFDIcon(Container);
export const ServerlessIcon = createDFDIcon(Zap);
export const ManagedServiceIcon = createDFDIcon(Cloud);
export const IAMRoleIcon = createDFDIcon(KeyRound);
