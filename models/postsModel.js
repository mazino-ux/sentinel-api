const mongoose =  require('mongoose');

const postSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Title is required'],
        trim: true,
        minLength: [3, 'Title must be at least 3 characters']
    },
    description: {
        type: String,
        required: [true, 'Description is required'],
        trim: true,
        minLength: [10, 'Description must be at least 10 characters']
    },
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is missing']
    }
}, {timestamps: true});

module.exports = mongoose.model('Post', postSchema);
// This model defines the structure of the post document in MongoDB.
// It includes fields for title, description, and userId (which references the User model).
// The title and description fields are required, with minimum length validations.
// The model is exported for use in other parts of the application, such as controllers and services.