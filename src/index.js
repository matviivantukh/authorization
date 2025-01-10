import "dotenv/config";
import express from "express";
import authRouter from "./routers/auth.js";

const app = express();

app.use((req, res, next) => {
  req.cookies = Object.fromEntries(
    req.headers.cookie.split("; ").map((cookieEntry) => cookieEntry.split("="))
  );
  next();
});
app.use(express.json());

app.use("/auth", authRouter);

app.listen(3000, () => {});
