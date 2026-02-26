const mongoose = require('mongoose');
const { isPostgres, initPostgres } = require('./postgres');

const connectDB = async () => {
  try {
    if (isPostgres) {
      await initPostgres();
      console.log('PostgreSQL connected');
      return;
    }

    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Database connection error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
