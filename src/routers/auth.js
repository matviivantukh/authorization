import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import * as db from "../db/index.js";

const authRouter = Router();

const generateAccessToken = async ({ client, user }) => {
  const tokenId = uuidv4();
  const accessToken = {
    id: tokenId,
    userId: user.id,
  };
  const token = jwt.sign(accessToken, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  const {
    rows: [createdToken],
  } = await client.query(
    "INSERT INTO access_tokens (id, token) VALUES ($1, $2) RETURNING *",
    [tokenId, token]
  );
  return createdToken;
};

const generateRefreshToken = async ({
  client,
  user,
  accessTokenId,
  deviceId,
}) => {
  const {
    rows: [createdToken],
  } = await client.query(
    "INSERT INTO refresh_tokens (token, access_token_id, user_id, device_id) VALUES ($1, $2, $3, $4) RETURNING *",
    [uuidv4(), accessTokenId, user.id, deviceId]
  );
  return createdToken;
};

const generateTokens = async ({ client, user, deviceId }) => {
  const accessToken = await generateAccessToken({ client, user });
  console.log(accessToken);
  const refreshToken = await generateRefreshToken({
    client,
    user,
    accessTokenId: accessToken.id,
    deviceId,
  });
  return { accessToken: accessToken.token, refreshToken: refreshToken.token };
};

const routeProtector = async (req, res, next) => {
  const { accessToken } = req.cookies;
  if (!accessToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    const {
      rows: [accessTokenFromDB],
    } = await db.query("SELECT * FROM access_tokens WHERE id = $1", [
      decoded.id,
    ]);
    if (!accessTokenFromDB) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

authRouter.post("/login", async (req, res) => {
  const { user, deviceId } = req.body;
  if (!user || !deviceId) {
    return res.status(400).json({ message: "User and deviceId are required" });
  }
  const { email, password } = user;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  const {
    rows: [userFromDB],
  } = await db.query("SELECT * FROM users WHERE email = $1 AND password = $2", [
    email,
    password,
  ]);
  if (!userFromDB) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  const {
    rows: [refreshTokenFromDB],
  } = await db.query(
    "SELECT * FROM refresh_tokens WHERE user_id = $1 and device_id = $2",
    [userFromDB.id, deviceId]
  );
  const transaction = await db.createTransaction();
  try {
    if (refreshTokenFromDB) {
      await transaction.query("DELETE FROM refresh_tokens WHERE token = $1", [
        refreshTokenFromDB.token,
      ]);
      await transaction.query("DELETE FROM access_tokens WHERE id = $1", [
        refreshTokenFromDB.access_token_id,
      ]);
    }
    const { accessToken, refreshToken } = await generateTokens({
      client: transaction,
      user: userFromDB,
      deviceId,
    });
    await transaction.commit();
    return res
      .status(200)
      .cookie("refreshToken", refreshToken)
      .cookie("accessToken", accessToken)
      .json({ user: userFromDB });
  } catch (error) {
    await transaction.rollback();
    return res.status(500).json({ message: error.message });
  }
});

authRouter.post("/register", async (req, res) => {
  const { user } = req.body;
  if (!user) {
    return res.status(400).json({ message: "User is required" });
  }
  const { email, password } = user;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  const {
    rows: [createdUser],
  } = await db.query(
    "INSERT INTO users (id, email, password) VALUES ($1, $2, $3) RETURNING *",
    [uuidv4(), email, password]
  );
  return res.status(201).json({ user: createdUser });
});

authRouter.post("/exchange-refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required" });
  }
  const {
    rows: [refreshTokenFromDB],
  } = await db.query("SELECT * FROM refresh_tokens WHERE token = $1", [
    refreshToken,
  ]);
  if (!refreshTokenFromDB) {
    return res.status(404).json({ message: "Refresh token not found" });
  }
  const {
    rows: [user],
  } = await db.query("SELECT * FROM users WHERE id = $1", [
    refreshTokenFromDB.user_id,
  ]);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  const transaction = await db.createTransaction();
  try {
    await transaction.query("DELETE FROM refresh_tokens WHERE token = $1", [
      refreshToken,
    ]);
    await transaction.query("DELETE FROM access_tokens WHERE id = $1", [
      refreshTokenFromDB.access_token_id,
    ]);
    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      await generateTokens({
        client: transaction,
        user: user,
        deviceId: refreshTokenFromDB.device_id,
      });
    await transaction.commit();
    return res
      .status(204)
      .cookie("refreshToken", newRefreshToken)
      .cookie("accessToken", newAccessToken)
      .send();
  } catch (error) {
    await transaction.rollback();
    return res.status(500).json({ message: error.message });
  }
});

authRouter.get("/account", routeProtector, async (req, res) => {
  const { userId } = req;
  const {
    rows: [user],
  } = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  return res.status(200).json({ user });
});

export default authRouter;
