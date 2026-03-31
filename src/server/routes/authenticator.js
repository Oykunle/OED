/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secretToken = require('../config').secretToken;
const User = require('../models/User');
const { log } = require('../log');
const validate = require('jsonschema').validate;
const { isTokenAuthorized, isUserAuthorized } = require('../util/userRoles');
const { getConnection } = require('../db');
const escapeHtml = require('escape-html');
const {
	PASSWORD_MAX_LENGTH,
	PASSWORD_MIN_LENGTH,
	TOKEN_MAX_LENGTH,
	USERNAME_MIN_LENGTH,
	USERNAME_MAX_LENGTH
} = require('../util/validationConstants');

/**
 * Middleware function to force a route to require authentication
 */
authMiddleware = (req, res, next) => {
	const token = req.headers.token || req.body.token || req.query.token;

	const validParams = {
		type: 'string',
		maxLength: TOKEN_MAX_LENGTH
	};

	if (!validate(token, validParams).valid) {
		res.status(403).json({ success: false, message: 'No token provided or JSON was invalid.' });
	} else if (token) {
		jwt.verify(token, secretToken, async (err, decoded) => {
			if (err) {
				res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
			} else {
				try {
					const conn = getConnection();

					// Ensure user exists
					const user = await User.getByID(decoded.data, conn);

					// 🔐 TOKEN INVALIDATION LOGIC
					const tokenIssuedAt = decoded.iat;
					const invalidBefore = user.tokenInvalidBefore
						? Math.floor(new Date(user.tokenInvalidBefore).getTime() / 1000)
						: 0;

					if (tokenIssuedAt < invalidBefore) {
						return res.status(401).json({
							success: false,
							message: 'Token invalidated.'
						});
					}

					req.decoded = decoded;
					next();
				} catch (error) {
					res.status(401).json({
						success: false,
						message: 'User does not exist in database.'
					});
				}
			}
		});
	} else {
		res.status(403).send({ success: false, message: 'No token provided.' });
	}
};

/**
 * Middleware that validates username/password request body
 */
function credentialsRequestValidationMiddleware(req, res, next) {
	const validParams = {
		type: 'object',
		required: ['username', 'password'],
		properties: {
			username: {
				type: 'string',
				minLength: USERNAME_MIN_LENGTH,
				maxLength: USERNAME_MAX_LENGTH
			},
			password: {
				type: 'string',
				minLength: PASSWORD_MIN_LENGTH,
				maxLength: PASSWORD_MAX_LENGTH
			}
		}
	};

	if (!validate(req.body, validParams).valid) {
		res.status(400).send('Invalid JSON. \n');
	} else {
		next();
	}
}

/**
 * Verify credentials
 */
async function verifyCredentials(username, password, returnUser = false) {
	const conn = getConnection();
	const user = await User.getByUsername(username, conn);

	let isValid;
	if (user === null) {
		isValid = false;
	} else {
		isValid = await bcrypt.compare(password, user.passwordHash);
	}

	return returnUser ? isValid && user : isValid;
}

/**
 * Role-based token middleware
 */
function roleTokenAuthMiddleware(role, action) {
	return function (req, res, next) {
		authMiddleware(req, res, async () => {
			const token = req.headers.token || req.body.token || req.query.token;

			if (await isTokenAuthorized(token, role)) {
				next();
			} else {
				log.warn(`Got request to '${action}' with invalid credentials.`);
				res.status(403).json({
					message: `Invalid credentials. Only ${role.toUpperCase()} can ${action}.`
				});
			}
		});
	};
}

function adminAuthMiddleware(action) {
	return roleTokenAuthMiddleware(User.role.ADMIN, action);
}

function exportAuthMiddleware(action) {
	return roleTokenAuthMiddleware(User.role.EXPORT, action);
}

function csvAuthMiddleware(action) {
	return roleTokenAuthMiddleware(User.role.CSV, action);
}

/**
 * Username/password auth for Obvius
 */
function obviusUsernameAndPasswordAuthMiddleware(action) {
	return function (req, res, next) {
		credentialsRequestValidationMiddleware(req, res, async () => {
			try {
				const user = await verifyCredentials(req.body.username, req.body.password, true);

				if (user) {
					if (isUserAuthorized(user, User.role.OBVIUS)) {
						next();
					} else {
						const message = `Invalid authorization level.`;
						log.warn(message);
						res.status(401).send(message);
					}
				} else {
					const message = `Invalid credentials.`;
					log.warn(message);
					res.status(400).send(message);
				}
			} catch (error) {
				if (error.message === 'No data returned from the query.') {
					res.status(400).send(
						`No user found for: ${escapeHtml(req.body.username)}`
					);
				} else {
					log.error('Internal Server Error', error);
					res.status(500).send('Internal OED Server Error.');
				}
			}
		});
	};
}

/**
 * Optional auth middleware
 */
optionalAuthMiddleware = (req, res, next) => {
	req.hasValidAuthToken = false;

	const token = req.headers.token || req.body.token || req.query.token;

	const validParams = {
		type: 'string',
		maxLength: TOKEN_MAX_LENGTH
	};

	if (!validate(token, validParams).valid) {
		next();
	} else if (token) {
		jwt.verify(token, secretToken, async (err, decoded) => {
			if (!err) {
				try {
					const conn = getConnection();
					const user = await User.getByID(decoded.data, conn);

					const tokenIssuedAt = decoded.iat;
					const invalidBefore = user.tokenInvalidBefore
						? Math.floor(new Date(user.tokenInvalidBefore).getTime() / 1000)
						: 0;

					if (tokenIssuedAt >= invalidBefore) {
						req.decoded = decoded;
						req.hasValidAuthToken = true;
					}
				} catch (error) {
					// ignore
				}
			}
			next();
		});
	} else {
		next();
	}
};

module.exports = {
	authMiddleware,
	adminAuthMiddleware,
	csvAuthMiddleware,
	exportAuthMiddleware,
	obviusUsernameAndPasswordAuthMiddleware,
	optionalAuthMiddleware,
	verifyCredentials,
	credentialsRequestValidationMiddleware
};
