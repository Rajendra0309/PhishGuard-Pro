const { MongoClient } = require('mongodb');

const DB_NAME = 'phishguard';
const COLLECTION_NAME = 'detection_results';
const MONGO_URL = 'mongodb://localhost:27017';

let dbClient = null;
let dbConnected = false;

async function connectDB() {
  if (dbConnected) return;
  
  try {
    dbClient = new MongoClient(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });
    await dbClient.connect();
    dbConnected = true;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    dbConnected = false;
  }
}

async function saveDetection(data) {
  try {
    await connectDB();
    if (!dbConnected) return false;
    
    const db = dbClient.db(DB_NAME);
    const collection = db.collection(COLLECTION_NAME);
    
    await collection.insertOne(data);
    return true;
  } catch (error) {
    console.error('MongoDB save error:', error);
    return false;
  }
}

async function getDetectionHistory(limit = 1000) {
  try {
    await connectDB();
    if (!dbConnected) return [];
    
    const db = dbClient.db(DB_NAME);
    const collection = db.collection(COLLECTION_NAME);
    
    return await collection.find({})
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
  } catch (error) {
    console.error('MongoDB query error:', error);
    return [];
  }
}

async function getStatistics() {
  try {
    await connectDB();
    if (!dbConnected) return null;
    
    const db = dbClient.db(DB_NAME);
    const collection = db.collection(COLLECTION_NAME);
    
    const totalScanned = await collection.countDocuments();
    const phishingDetected = await collection.countDocuments({ 'result.isPhishing': true });
    
    return { totalScanned, phishingDetected };
  } catch (error) {
    console.error('MongoDB stats error:', error);
    return null;
  }
}

module.exports = { saveDetection, getDetectionHistory, getStatistics };
