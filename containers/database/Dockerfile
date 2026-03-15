# *
# * This Source Code Form is subject to the terms of the Mozilla Public
# * License, v. 2.0. If a copy of the MPL was not distributed with this
# * file, You can obtain one at http://mozilla.org/MPL/2.0/.
# *

# Dockerfile for OED Postgres server.
# Use a pinned version
FROM postgres:15.3

# Copy SQL and shell init files into the Postgres init directory.
COPY *.sql *.sh /docker-entrypoint-initdb.d/

# Ensure shell init files are executable.
RUN chmod +x /docker-entrypoint-initdb.d/*.sh
