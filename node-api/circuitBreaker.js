class CircuitBreaker {
  constructor({ failureThreshold = 3, resetTimeout = 10000 }) {
    this.failureThreshold = failureThreshold;
    this.resetTimeout = resetTimeout;
    this.failureCount = 0;
    this.state = "CLOSED";
    this.nextAttempt = Date.now();
  }

  async execute(action) {
    if (this.state === "OPEN") {
      if (Date.now() > this.nextAttempt) {
        this.state = "HALF_OPEN";
      } else {
        throw new Error("Circuit breaker is OPEN");
      }
    }

    try {
      const result = await action();
      this.failureCount = 0;
      this.state = "CLOSED";
      return result;
    } catch (err) {
      this.failureCount++;
      if (this.failureCount >= this.failureThreshold) {
        this.state = "OPEN";
        this.nextAttempt = Date.now() + this.resetTimeout;
      }
      throw err;
    }
  }
}

module.exports = CircuitBreaker;
