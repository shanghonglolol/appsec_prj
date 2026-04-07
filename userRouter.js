const router = require('express').Router();

const { memberSignup, memberLogin, memberAuth, checkRole } 
= require("../Controller/authFunctions");

//Member Registration Route
router.post("/register-member", (req, res) => {
    memberSignup(req.body, "member", res);
});

//President Registration Route
router.post("/register-president", async (req, res) => {
    await memberSignup(req.body, "president", res);
});

//Treasurer Registration Route
router.post("/register-treasurer", async (req, res) => {
    await memberSignup(req.body, "treasurer", res);
});

//Secretary Registration Route
router.post("/register-secretary", async (req, res) => {
    await memberSignup(req.body, "secretary", res);
});

// Member Login Route
router.post("/login-member", async (req, res) => {
    await memberLogin(req.body, "member", res);
});

// President Login Route
router.post("/login-president", async (req, res) => {
    await memberLogin(req.body, "president", res);
});

// Treasurer Login Route
router.post("/login-treasurer", async (req, res) => {
    await memberLogin(req.body, "treasurer", res);
});

// Secretary Login Route
router.post("/login-secretary", async (req, res) => {
    await memberLogin(req.body, "secretary", res);
});

//member protected route
router.get(
    "/member-protected",
    memberAuth,
    checkRole(["member"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);
 
 
//president protected route
router.get(
    "/president-protected",
    memberAuth,
    checkRole(["president"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);

//treasurer protected route
router.get(
    "/treasurer-protected",
    memberAuth,
    checkRole(["treasurer"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);

//secretary protected route
router.get(
    "/secretary-protected",
    memberAuth,
    checkRole(["secretary"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);

//public unprotected route
router.get(
    "/public", (req, res) => {
        return res.status(200).json("Public Domain");
    });


module.exports = router;