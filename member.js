// importing schema and model from mongoose module
const { Schema, model } = require('mongoose');

// defining schema for member
const MemberSchema = new Schema(
    {
        // name field of member
        name: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },
        // email field of member
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },
        // role field of member - 4 roles total
        role: {
            type: String,
            enum: ["member", "president", "treasurer", "secretary"],
            required: true
        },
        //password field of member
        password: {
            type: String,
            required: true,
        },
        // Track login status for logout
        isLoggedIn: {
            type: Boolean,
            default: false
        },
        activeToken: {
            type: String,
            default: null
        },

        resetPasswordToken: {
            type: String,
            default: null
        },
        resetPasswordExpires: {
            type: Date,
            default: null
        }
    },
    { timestamps: true }
);

//exporting the member model
module.exports = model("Member", MemberSchema);