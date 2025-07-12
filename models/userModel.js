const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is Required'],
        unique: [true, 'Username Already Exist'],
        minLength: [3, 'Username must be more than 4 characters!']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        unique: [true, 'Email Already Exists'],
        minLength: [5, 'Email must be at least 5 characters'],
        lowercase: true
    },
    password: {
        type: String,
        required: [true, 'Password must be provided'],
        trim: true,
        minLength: [6, 'Password must be at least 6 characters'],
        select: false
    },
    verified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String,
        default: '',
        select: false
    },
    verificationTokenValidation: {
        type: Number,
        select: false
    },
    forgotPasswordCode: {
        type: String,
        select: false
    },
    forgotPasswordCodeValidation: {
        type: Number,
        select: false
    },
},{
    timestamps: true
});

module.exports = mongoose.model('User', userSchema);
// This model defines the structure of the user document in MongoDB.
// It includes fields for username, email, password, verification status, and tokens for verification and password reset.
// The schema also includes timestamps for created and updated times.
// The model is exported for use in other parts of the application, such as controllers and services. and password reset functionalities.