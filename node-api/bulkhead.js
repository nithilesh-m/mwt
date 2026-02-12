class Bulkhead {
  constructor(limit) {
    this.limit = limit;
    this.active = 0;
  }

  async execute(task) {
    if (this.active >= this.limit) {
      throw new Error("Bulkhead limit exceeded");
    }
    this.active++;
    try {
      return await task();
    } finally {
      this.active--;
    }
  }
}

module.exports = Bulkhead;
