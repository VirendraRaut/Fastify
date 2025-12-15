// const fp = require("fastify-plugin");
// const mongoose = require("mongoose");

// module.exports = fp(async (fastify, opts) => {
//   try {
//     await mongoose.connect(process.env.MONGODB_URI);
//     fastify.decorate("mongoose", mongoose);
//     fastify.log.info("MONGODB connected !");
//   } catch (err) {
//     fastify.log.error(err);
//     process.exit(1);
//   }
// });

const fp = require("fastify-plugin");
const mongoose = require("mongoose");

module.exports = fp(async (fastify) => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    fastify.decorate("mongoose", mongoose);
    fastify.log.info("MongoDB connected");
  } catch (err) {
    fastify.log.error(err);
    throw err; // let Fastify handle startup failure
  }
});
