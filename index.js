const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const authRouter = require('./routers/authRouter');

const app = express();
app.use(cors());
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log('✅ Database Connected Successfully!')
    })
    .catch((err) => {
        console.log('❌ Database Connection Failed:', err);
    })

app.use('/api/auth', authRouter);

app.get('/', (req, res) => {
    res.json({message: 'Hello, From the Server!'});
})

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
})