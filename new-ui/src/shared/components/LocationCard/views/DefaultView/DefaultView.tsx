import { useMutation } from '@tanstack/react-query';
import { Fragment } from 'react/jsx-runtime';
import { api } from '../../../../rust-api/api';
import { ThemeSpacing } from '../../../../types';
import { shouldStartMfa } from '../../../../utils/mfa';
import { canChooseRouting, lockedRoutingLabel } from '../../../../utils/trafficPolicy';
import { Divider } from '../../../Divider/Divider';
import { SizedBox } from '../../../SizedBox/SizedBox';
import { Toggle } from '../../../Toggle/Toggle';
import { LocationCardConnectButton } from '../../components/LocationCardConnectButton';
import { LocationCardMfaEdit } from '../../components/LocationCardMfaEdit/LocationCardMfaEdit';
import { useLocationCardContext } from '../../context/context';
import { LocationCardViews } from '../../context/types';

export const DefaultView = () => {
  const { location, instance, setView, connectionAbility } = useLocationCardContext();

  const { mutate: updateRouting } = useMutation({
    mutationFn: api.updateLocationRouting,
    meta: {
      invalidate: ['locations'],
    },
  });

  return (
    <div className="location-view-default">
      {!canChooseRouting(instance?.client_traffic_policy) && (
        <Fragment>
          <Divider spacing={ThemeSpacing.Md} />
          <p className="locked-routing">
            {lockedRoutingLabel(instance?.client_traffic_policy)}
          </p>
        </Fragment>
      )}
      {canChooseRouting(instance?.client_traffic_policy) && (
        <Fragment>
          <Divider spacing={ThemeSpacing.Md} />
          <Toggle
            disabled={location.active}
            active={location.route_all_traffic}
            label={
              location.route_all_traffic
                ? 'All traffic is allowed'
                : 'Predefined traffic only'
            }
            onClick={() => {
              updateRouting({
                connectionType: location.connection_type,
                locationId: location.id,
                routeAllTraffic: !location.route_all_traffic,
              });
            }}
          />
        </Fragment>
      )}
      {shouldStartMfa(location) && (
        <Fragment>
          <Divider spacing={ThemeSpacing.Md} />
          <LocationCardMfaEdit
            variant="compact"
            location={location}
            instance={instance}
            connectionAbility={connectionAbility}
            onEdit={() => {
              setView(LocationCardViews.MfaSettings);
            }}
          />
        </Fragment>
      )}
      <SizedBox height={ThemeSpacing.Xl3} />
      <LocationCardConnectButton />
    </div>
  );
};
