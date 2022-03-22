require('dotenv').config();

const urlencoded = require('body-parser/lib/types/urlencoded');
const express = require('express');
const app = express();
const port = process.env.PORT;
const mongoose = require('mongoose');

app.use(express.json())

//Routes
const authRoutes = require('./routes/auth');

//Declare API category endpoints
app.use('/api/auth',authRoutes)

//MongoDB connection
const dbURI = process.env.URI
mongoose.connect(dbURI)
    .then((result) => app.listen(port))
    .catch((err) => console.log(err))
console.log(`API listening to http://localhost:${port}...`);

