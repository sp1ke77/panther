/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import { LogIntegration } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';
import { Alert, Table } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import { useListLogSources } from './graphql/listLogSources.generated';
import columns from '../columns';

const LogSourceTable = () => {
  const { loading, error, data } = useListLogSources({
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
    return <TablePlaceholder />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your sources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Table<LogIntegration>
      items={data.listLogIntegrations}
      getItemKey={item => item.integrationId}
      columns={columns}
    />
  );
};

export default React.memo(LogSourceTable);