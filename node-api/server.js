const express = require("express");
const redis = require("redis");
const Bulkhead = require("./bulkhead");
const CircuitBreaker = require("./circuitBreaker");
const log = require("./logger");
const fetch = require("node-fetch");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const redisClient = redis.createClient();
redisClient.connect();

const bulkhead = new Bulkhead(2);
const breaker = new CircuitBreaker({ failureThreshold: 3 });

app.post("/submit", async (req, res) => {
  const idemKey = req.headers["idempotency-key"];
  const orderId = req.body.orderId;

  if (!idemKey) {
    return res.status(400).json({ error: "Missing Idempotency-Key" });
  }

  // IDEMPOTENCY
  if (await redisClient.get(idemKey)) {
    return res.json({ message: "Duplicate request ignored" });
  }

  try {
    await bulkhead.execute(() =>
        breaker.execute(async () => {
            // SIMULATE slow dependency
            await new Promise(res => setTimeout(res, 5000));

            await fetch("http://localhost:5001/enqueue", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ orderId })
            });
        })
    );

    await redisClient.set(idemKey, "done", { EX: 300 });
    log(`Order ${orderId} submitted`);

    res.json({ status: "submitted" });
  } catch (err) {
    log(err.message);
    res.status(503).json({
      error: err.message,
      breakerState: breaker.state
    });
  }
});

app.listen(3000, () => {
  console.log("Node API running on http://localhost:3000");
});
