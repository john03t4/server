const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Ensure crypto is imported

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'apexcart30@gmail.com', // Replace with your email
        pass: 'uszioppnrucyztan'  // Replace with your password
    }
});


// Function to connect to a user's personal database
const getUserDB = (email) => {
    return new Sequelize({
        dialect: 'sqlite',
        storage: `databases/${email}.db`,  // Use backticks here
        logging: false,
    });
};

// Initialize Sequelize with SQLite using "All.db"
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'All.db', // This ensures data is saved persistently in All.db
    logging: false, // Disable logging to keep it clean
});

// Define User model with trial expiration
const User = sequelize.define('User', {
    fullName: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    status: { type: DataTypes.STRING, defaultValue: 'offline' },
    profilePicture: { type: DataTypes.STRING, allowNull: true },
    trialEndsAt: { type: DataTypes.DATE, allowNull: true, defaultValue: Sequelize.NOW },
    subscriptionPlan: { type: DataTypes.STRING, allowNull: true },
    emailVerified: { type: DataTypes.BOOLEAN, defaultValue: false }, // ✅ Added field
    emailVerificationToken: { type: DataTypes.STRING, allowNull: true }, // ✅ Stores token
    tokenExpiresAt: { type: DataTypes.DATE, allowNull: true } // ✅ Expiration time for token
});

// Define PasswordResetToken model
const PasswordResetToken = sequelize.define('PasswordResetToken', {
    email: { type: DataTypes.STRING, allowNull: false },
    resetToken: { type: DataTypes.STRING, allowNull: false },
    expiresAt: { type: DataTypes.DATE, allowNull: false },
});
const defineProductModel = (userDB) => {
    const Product = userDB.define('Product', {
        productId: { 
            type: DataTypes.INTEGER, 
            allowNull: false, 
            unique: true, 
            defaultValue: () => Math.floor(10000 + Math.random() * 90000) // Generates unique ID
        },
        name: { type: DataTypes.STRING, allowNull: false },
        price: { type: DataTypes.FLOAT, allowNull: false },
        image: { type: DataTypes.STRING, allowNull: true },
        description: { type: DataTypes.TEXT, allowNull: true },
        inStore: { type: DataTypes.BOOLEAN, defaultValue: false }
    });

    Product.sync()

    return Product;
};



// ✅ Initialize Global Shop Database First
const globalDB = new Sequelize({
    dialect: 'sqlite',
    storage: './global_shop.db', // Dedicated database for shop products
    logging: false // Disable logging
});

// ✅ Define Global `ShopProduct` Model (For `inShop` Products)
const ShopProduct = globalDB.define('ShopProduct', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    productId: { type: DataTypes.INTEGER, allowNull: false, unique: true },
    userEmail: { type: DataTypes.STRING, allowNull: false },
    name: { type: DataTypes.STRING, allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
    image: { type: DataTypes.STRING, allowNull: true },
    description: { type: DataTypes.TEXT, allowNull: true }
}, { timestamps: true });

// ✅ Force Sync to Recreate Table if Schema is Wrong
globalDB.sync()

// ✅ Define `inShopProducts` Table in User Database (Tracks Added Products)
const defineShopProductModel = (userDB) => {
    return userDB.define('inShopProducts', {
        productId: { type: DataTypes.INTEGER, allowNull: false, unique: true }
    });
};

// Custom middleware for checking the user and ensuring the Product table exists
function defineUserFromRequest(req, res, next) {
    // Extract the email either from the request body or a custom header (x-user-email)
    const email = req.body.email || req.headers['x-user-email'];

    // If email is not found, respond with an authentication required message
    if (!email) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    // Look up the user in the database based on the email
    User.findOne({ where: { email } })
        .then(user => {
            if (!user) {
                // If the user is not found, return a 404 response
                return res.status(404).json({ message: 'User not found' });
            }


            // Attach the user to the request object so other middleware/handlers can access it
            req.user = user;

            // Connect to the user's specific database and ensure the Product table exists
            const userDB = getUserDB(email);  // Get the user's personal database
            defineProductModel(userDB);  // Define the Product model (this ensures the Product table exists)

            // Proceed to the next middleware or route handler
            next();
        })
        .catch(error => {
            // Log and handle any errors that occur during the process
            console.error("Error in authentication middleware:", error);
            return res.status(500).json({ message: 'Internal server error' });
        });
}



// Set up storage for uploaded files
const storage = multer.diskStorage({
    destination: './uploads/', // Save images to 'uploads' folder
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
    }
});

const upload = multer({ storage: storage });

// Synchronize models with database
sequelize.sync({ force: false }).then(() => {
    console.log("Database connected and models synced");
}).catch(error => {
    console.error("Error syncing database:", error);
});

// Function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Register Route
app.post('/register', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!isValidEmail(email)) {
        return res.status(400).json({ message: "❌ Invalid email format." });
    }

    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: "❌ Email already registered." });
        }

        const trialEndsAt = new Date();
        trialEndsAt.setDate(trialEndsAt.getDate() + 7);

        const newUser = await User.create({ fullName, email, password, trialEndsAt });

        res.status(201).json({ message: "✅ Registration successful", user: newUser });
    } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Check if the password matches
        if (user.password !== password) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        user.status = 'online';
        await user.save();

        res.json({
            message: 'Login successful',
            user: { id: user.id, email: user.email, fullName: user.fullName },
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// 🔹 Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: '❌ Email is required.' });

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(404).json({ message: '❌ User not found.' });

        const resetToken = crypto.randomBytes(3).toString('hex').toUpperCase(); // ✅ 6-char uppercase token
        const expirationTime = new Date(Date.now() + 60 * 60 * 1000); // ✅ 1 hour expiry

        await PasswordResetToken.upsert({ email, resetToken, expiresAt: expirationTime });

        const mailOptions = {
            from: 'support@apex-cart.com',
            to: email,
            subject: '🔑 Password Reset Token',
            text: `Your password reset token is: ${resetToken}\n\nThis token will expire in 1 hour.`
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: '✅ Password reset token sent to your email.' });
    } catch (error) {
        console.error('❌ Error during forgot password:', error);
        res.status(500).json({ message: '❌ Server error. Please try again later.' });
    }
});

// 🔹 Verify Reset Token Route
app.post('/verify-token', async (req, res) => {
    const { email, token } = req.body;

    if (!email || !token) return res.status(400).json({ message: '❌ Email and token are required.' });

    try {
        const tokenData = await PasswordResetToken.findOne({ where: { email, resetToken: token } });

        if (!tokenData) return res.status(400).json({ message: '❌ Invalid token.' });
        if (new Date() > new Date(tokenData.expiresAt)) {
            await PasswordResetToken.destroy({ where: { email } });
            return res.status(400).json({ message: '❌ Token expired. Request a new one.' });
        }

        res.json({ message: '✅ Token verified. Proceed to reset password.' });
    } catch (error) {
        console.error('❌ Error verifying token:', error);
        res.status(500).json({ message: '❌ Server error.' });
    }
});

// 🔹 Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
        return res.status(400).json({ message: '❌ All fields are required.' });
    }

    try {
        const tokenData = await PasswordResetToken.findOne({ where: { email, resetToken: token } });

        if (!tokenData) return res.status(400).json({ message: '❌ Invalid token.' });
        if (new Date() > new Date(tokenData.expiresAt)) {
            await PasswordResetToken.destroy({ where: { email } });
            return res.status(400).json({ message: '❌ Token expired. Request a new one.' });
        }

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(404).json({ message: '❌ User not found.' });

        user.password = newPassword;
        await user.save();
        await PasswordResetToken.destroy({ where: { email } });

        res.json({ message: '✅ Password reset successful. Redirecting to login...' });
    } catch (error) {
        console.error('❌ Error during password reset:', error);
        res.status(500).json({ message: '❌ Server error.' });
    }
});

// Send verification email using userEmail from localStorage
app.post('/send-verification-email', async (req, res) => {
    const { email } = req.body;

    if (!isValidEmail(email)) {
        return res.status(400).json({ message: "❌ Invalid email address." });
    }

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: "❌ User not found." });
        }

        if (user.emailVerified) {
            return res.json({ message: "✅ Email is already verified." });
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24-hour expiry

        user.emailVerificationToken = verificationToken;
        user.tokenExpiresAt = tokenExpiration;
        await user.save();

        const verificationLink = `https://server-tigx.onrender.com/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: 'support@apex-cart.com',
            to: email,
            subject: 'Verify Your Email - ApexCart',
            html: `<p>Click below to verify your email:</p>
                   <a href="${verificationLink}">${verificationLink}</a>
                   <p>This link expires in 24 hours.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: "✅ Verification email sent successfully!" });

    } catch (error) {
        console.error("❌ Server error:", error);
        res.status(500).json({ message: "❌ Server error." });
    }
});

// Verify Email when user taps the link
app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        const user = await User.findOne({ where: { emailVerificationToken: token } });

        if (!user) {
            return res.status(400).json({ success: false, message: "❌ Invalid or expired verification token." });
        }

        if (new Date() > new Date(user.tokenExpiresAt)) {
            return res.status(400).json({ success: false, message: "❌ Verification link expired. Please request a new one." });
        }

        // ✅ Save emailVerified to the database
        user.emailVerified = true; 
        user.emailVerificationToken = null; // Remove token after verification
        await user.save();

        res.json({ 
            success: true, 
            message: "✅ Email verified successfully!", 
            emailVerified: user.emailVerified  // ✅ Return verification status
        });

    } catch (error) {
        console.error("❌ Error verifying email:", error);
        res.status(500).json({ success: false, message: "❌ Server error." });
    }
});

// Find User
app.get('/user/:email', async (req, res) => {
    const { email } = req.params;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: "❌ User not found" });
        }

        res.json({ 
            name: user.fullName, 
            email: user.email, 
            emailVerified: user.emailVerified  // ✅ Fetch verification status from database
        });

    } catch (error) {
        console.error("❌ Error fetching user info:", error);
        res.status(500).json({ message: "❌ Server error" });
    }
});



// Logout Route
app.post('/logout', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (user) {
            user.status = 'offline'; // Set status to offline
            await user.save();
        }

        res.json({ message: 'Logout successful' });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ message: 'An error occurred during logout' });
    }
});


// Admin Dashboard Route - Fetch All Users (Online & Offline)
app.get('/admin/dashboard', async (req, res) => {
    try {
        const allUsers = await User.findAll(); // Fetch all users, regardless of status
        res.json({ users: allUsers });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).json({ message: 'An error occurred during data fetch' });
    }
});

// Delete User Route (Also Deletes User Database)
app.delete('/admin/users/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const user = await User.findByPk(userId);

        if (!user) {
            return res.status(404).json({ message: "❌ User not found" });
        }

        const userEmail = user.email;
        const userDBPath = path.join(__dirname, `databases/${userEmail}.db`);

        // Delete user database file if it exists
        if (fs.existsSync(userDBPath)) {
            fs.unlinkSync(userDBPath);
            console.log(`✅ Deleted database: ${userDBPath}`);
        } else {
            console.log(`⚠️ No database found for user: ${userEmail}`);
        }

        // Delete user from the main database
        await user.destroy();

        res.json({ message: "✅ User and associated database deleted successfully" });
    } catch (error) {
        console.error('❌ Error deleting user:', error);
        res.status(500).json({ message: "❌ An error occurred while deleting the user" });
    }
});



// Upload Profile Picture Route
app.post('/upload-profile', upload.single('profilePicture'), async (req, res) => {
    const { email } = req.body;
    if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
    }

    const profilePictureUrl = `http://localhost:5000/uploads/${req.file.filename}`;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        user.profilePicture = profilePictureUrl;
        await user.save();

        res.json({ message: "Profile picture uploaded successfully", profilePicture: profilePictureUrl });
    } catch (error) {
        console.error("Error uploading profile picture:", error);
        res.status(500).json({ message: "An error occurred while uploading the profile picture" });
    }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('/user/:email', async (req, res) => {
    const userEmail = req.params.email;

    try {
        const user = await User.findOne({ where: { email: userEmail } });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ name: user.fullName, email: user.email });
    } catch (error) {
        console.error("Error fetching user info:", error);
        res.status(500).json({ message: "An error occurred while fetching user info" });
    }
});

// **🔹 GET PRODUCTS ROUTE (Retrieves all products from user database)**
app.get('/get-products/:email', async (req, res) => {
    const { email } = req.params;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: "❌ User not found" });
        }

        // Check if trial has expired
        if (new Date() > new Date(user.trialEndsAt)) {
            return res.status(403).json({ message: "🚫 Trial period expired. Please upgrade." });
        }

        // Connect to the user's database
        const userDB = getUserDB(email);
        await userDB.sync();

        const Product = defineProductModel(userDB);
        await Product.sync();

        const products = await Product.findAll();
        res.json({ products });
    } catch (error) {
        console.error("❌ Error retrieving products:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});

// **🔹 DELETE PRODUCT ROUTE**
// Delete Product Route
app.delete('/delete-product', async (req, res) => {
    const { email, productId } = req.body;

    if (!productId || !email) {
        return res.status(400).json({ message: "❌ Missing required fields" });
    }

    try {
        // Connect to the user's database
        const userDB = getUserDB(email);
        await userDB.sync();

        const Product = defineProductModel(userDB);

        // Delete the product
        const deleted = await Product.destroy({ where: { id: productId } });

        if (deleted) {
            res.json({ message: "✅ Product deleted successfully" });
        } else {
            res.status(404).json({ message: "❌ Product not found" });
        }
    } catch (error) {
        console.error("❌ Error deleting product:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});

// Endpoint to get products, needs user to be authenticated
app.get('/products/:email',   async (req, res) => {
    const { email } = req.params;
    try {
        const userDB = getUserDB(email);
        const Product = defineProductModel(userDB);
        const products = await Product.findAll();
        res.json(products);
    } catch (error) {
        console.error("❌ Error retrieving products:", error);
        res.status(500).json({ error: 'Error retrieving products' });
    }
});

// Endpoint to get all products from the user's store
app.get('/store-products', defineUserFromRequest, async (req, res) => {
    try {
        const { email } = req.user;
        const userDB = getUserDB(email);
        const Product = defineProductModel(userDB);

        // ✅ Ensure `productId` is included
        const products = await Product.findAll({
            where: { inStore: true },
            attributes: ['productId', 'name', 'price', 'image', 'description']
        });

        res.json(products);
    } catch (error) {
        console.error("❌ Error retrieving products:", error);
        res.status(500).json({ message: '❌ Error retrieving products from store' });
    }
});




// Add to Store
app.post('/add-to-store', defineUserFromRequest, async (req, res) => {
    const { productId, email } = req.body;

    if (!email) {
        console.log('❌ No email provided.');
        return res.status(400).json({ message: '❌ User email is required' });
    }

    if (!productId) {
        console.log('❌ No product ID provided.');
        return res.status(400).json({ message: '❌ Product ID is required' });
    }

    try {
        const userDB = getUserDB(email);  // Get the user's specific database
        const Product = defineProductModel(userDB);  // Define the Product model for this user

        const product = await Product.findByPk(productId);
        if (!product) {
            console.log(`❌ Product with ID ${productId} not found.`);
            return res.status(404).json({ message: '❌ Product not found' });
        }

        // Check if the product is already in the store
        if (product.inStore) {
            console.log(`❌ Product ${productId} is already in the store.`);
            return res.status(400).json({ message: '❌ Product is already in the store' });
        }

        // Mark the product as in the store
        product.inStore = true;
        await product.save();  // Update product in the database

        res.json({ message: '✅ Product added to store successfully!' });
    } catch (error) {
        console.error('❌ Error adding product to store:', error);
        res.status(500).json({ message: '❌ Error adding product to store' });
    }
});


// Remove from Store
app.delete('/remove-from-store', defineUserFromRequest, async (req, res) => {
    const { productId, email } = req.body;

    if (!email) {
        return res.status(400).json({ message: '❌ User email is required' });
    }

    try {
        const userDB = getUserDB(email);
        const Product = defineProductModel(userDB);

        const product = await Product.findByPk(productId);
        if (!product) {
            return res.status(404).json({ message: '❌ Product not found' });
        }

        // Check if the product is in the store before trying to remove it
        if (!product.inStore) {
            return res.status(400).json({ message: '❌ Product is not in the store' });
        }

        // Remove the product from the store
        product.inStore = false;
        await product.save();  // Update product in the database

        res.json({ message: '✅ Product removed from store successfully!' });
    } catch (error) {
        console.error("❌ Error removing product from store:", error);
        res.status(500).json({ message: '❌ Error removing product from store' });
    }
});

app.post('/add-to-shop', async (req, res) => {
    try {
        const { productId } = req.body;
        const email = req.headers['x-user-email'];

        if (!email || !productId) {
            return res.status(400).json({ message: "❌ Email and Product ID are required." });
        }

        const userDB = getUserDB(email);
        await userDB.sync();
        const Product = defineProductModel(userDB);
        await Product.sync();

        const product = await Product.findOne({ where: { productId } });
        if (!product) {
            return res.status(404).json({ message: "❌ Product not found." });
        }

        const existingShopProduct = await ShopProduct.findOne({ where: { productId } });
        if (existingShopProduct) {
            return res.status(400).json({ message: "❌ Product is already in the shop." });
        }

        await ShopProduct.create({
            productId: product.productId,
            userEmail: email,
            name: product.name,
            price: product.price,
            image: product.image,
            description: product.description
        });

        res.json({ message: "✅ Product added to shop successfully!" });
    } catch (error) {
        console.error("❌ Error adding product to shop:", error);
        res.status(500).json({ message: "❌ Server error" });
    }
});



// ✅ Remove from Shop (Removes from Both User & Global Databases)
app.post('/remove-from-shop', async (req, res) => {
    try {
        const { productId } = req.body;
        const email = req.headers['x-user-email']; // ✅ Fetch Email from Headers

        if (!email || !productId) {
            return res.status(400).json({ message: "❌ Email and Product ID are required." });
        }

        // ✅ Connect to User Database & Define Model
        const userDB = getUserDB(email);
        await userDB.sync();
        const UserShopProduct = defineShopProductModel(userDB);
        await UserShopProduct.sync();

        // ✅ Ensure Product Exists in Shop Before Removing
        const productToRemove = await ShopProduct.findOne({ where: { productId, userEmail: email } });
        if (!productToRemove) {
            return res.status(404).json({ message: "❌ Product not found in shop." });
        }

        // ✅ Remove Product from User's `inShopProducts` Table
        await UserShopProduct.destroy({ where: { productId } });

        // ✅ Remove Product from Global Shop Database
        await ShopProduct.destroy({ where: { productId, userEmail: email } });

        res.json({ message: "✅ Product removed from shop successfully!" });
    } catch (error) {
        console.error("❌ Error removing product from shop:", error);
        res.status(500).json({ message: "❌ Server error" });
    }
});

// **🔹 Endpoint to edit a product**
app.put('/edit-product', async (req, res) => {
    const { email, productId, name, price, image, description } = req.body;

    if (!email || !productId) {
        return res.status(400).json({ message: "❌ Missing required fields" });
    }

    try {
        // **🔹 Connect to the user's database**
        const userDB = getUserDB(email);
        await userDB.sync();

        // **🔹 Define the Product model**
        const Product = defineProductModel(userDB);
        await Product.sync(); // Ensure table exists

        // **🔹 Find the product by `id` and update it**
        const updatedRows = await Product.update(
            { name, price, image, description }, // New data
            { where: { id: productId } } // Filter by `id`
        );

        if (updatedRows[0] === 0) {
            return res.status(404).json({ message: "❌ Product not found" });
        }

        res.json({ message: "✅ Product updated successfully!" });
    } catch (error) {
        console.error("❌ Error editing product:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});


// **🔹 Add Product Route**
app.post('/add-product', async (req, res) => {
    const { email, name, price, image, description } = req.body;

    // Validate required fields
    if (!email || !name || !price) {
        return res.status(400).json({ message: "❌ Missing required fields" });
    }

    try {
        // **🔹 Connect to the user's database**
        const userDB = getUserDB(email);
        await userDB.sync();  // Make sure the user's DB is connected and in sync

        // **🔹 Define the Product model**
        const Product = defineProductModel(userDB);
        await Product.sync();  // Ensure the table exists

        // **🔹 Check for existing product with the same name**
        const existingProduct = await Product.findOne({ where: { name } });
        if (existingProduct) {
            return res.status(400).json({ message: "❌ Product with this name already exists" });
        }

        // **🔹 Create the new product**
        const newProduct = await Product.create({ name, price, image, description });

        // Respond with success
        res.status(201).json({ message: "✅ Product added successfully!", product: newProduct });
    } catch (error) {
        console.error("❌ Error adding product:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});


// Endpoint to fetch products for the logged-in user
app.get('/api/products', async (req, res) => {
    const { email } = req.user; // Get email of the logged-in user (from session or JWT)
    
    try {
        // Access the user's personal database
        const userDB = getUserDB(email); // Assuming this function returns Sequelize DB connection for the user
        await userDB.sync(); // Sync the user-specific database

        // Define the Product model dynamically for each user
        const Product = userDB.define('Product', {
            name: {
                type: DataTypes.STRING,
                allowNull: false
            },
            price: {
                type: DataTypes.FLOAT,
                allowNull: false
            },
            image: {
                type: DataTypes.STRING,
                allowNull: false
            },
            description: {
                type: DataTypes.STRING,
                allowNull: false
            }
        });

        // Fetch products for the logged-in user
        const products = await Product.findAll();
        
        // Return the products as a response
        res.json({ products });

    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ message: 'Error fetching products' });
    }
});

// Endpoint to delete a product
app.delete('/delete-product', async (req, res) => {
    const { productId } = req.body;
    try {
        const { email } = req.user;  // Get email from logged-in user
        const userDB = getUserDB(email);
        const Product = userDB.define('Product', {
            name: DataTypes.STRING,
            price: DataTypes.FLOAT,
            image: DataTypes.STRING,
            description: DataTypes.STRING,
        });

        await Product.destroy({
            where: { id: productId }
        });

        res.json({ message: 'Product deleted successfully!' });
    } catch (error) {
        console.error("❌ Error deleting product:", error);
        res.status(500).json({ message: 'Error deleting product' });
    }
});

app.get('/check-trial-status/:email', async (req, res) => {
    const { email } = req.params;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: "❌ User not found" });
        }

        const currentDate = new Date();
        const trialExpired = currentDate > new Date(user.trialEndsAt);

        res.json({ trialExpired, trialEndsAt: user.trialEndsAt });
    } catch (error) {
        console.error("❌ Error checking trial status:", error);
        res.status(500).json({ message: "❌ Server error", error: error.message });
    }
});

// Define available subscription plans
const subscriptionPlans = [
    { id: 1, name: "Basic Plan", price: 9.99, duration: "monthly" },
    { id: 2, name: "Pro Plan", price: 19.99, duration: "monthly" },
    { id: 3, name: "Enterprise Plan", price: 49.99, duration: "monthly" }
];

// Route to fetch all subscription plans
app.get("/subscription/plans", (req, res) => {
    res.json({ success: true, plans: subscriptionPlans });
});

// Route to store user's selected subscription plan (without auto redirect)
app.post("/subscription/choose", async (req, res) => {
    const { email, planId } = req.body;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const selectedPlan = subscriptionPlans.find(plan => plan.id === parseInt(planId));

        if (!selectedPlan) {
            return res.status(400).json({ success: false, message: "Invalid subscription plan." });
        }

        user.subscriptionPlan = selectedPlan.name;
        await user.save();

        res.json({
            success: true,
            message: `Subscription updated to ${selectedPlan.name}.`
        });
    } catch (error) {
        console.error("Error selecting subscription plan:", error);
        res.status(500).json({ success: false, message: "Server error." });
    }
});


// Route to get user's selected subscription plan
app.get("/subscription/selected/:email", async (req, res) => {
    const { email } = req.params;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user || !user.subscriptionPlan) {
            return res.status(404).json({ success: false, message: "No subscription plan selected." });
        }

        res.json({ success: true, plan: user.subscriptionPlan });
    } catch (error) {
        console.error("Error fetching subscription plan:", error);
        res.status(500).json({ success: false, message: "Server error." });
    }
});

// ✅ API to Fetch `inShop` Products (From Global Shop Database)
app.get('/shop-products', async (req, res) => {
    try {
        const products = await ShopProduct.findAll();
        res.json(products);
    } catch (error) {
        console.error('❌ Error fetching shop products:', error);
        res.status(500).json({ message: '❌ Server error' });
    }
});

// Fetch product details by productId
app.get('/get-product/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        const product = await ShopProduct.findOne({ where: { productId } });

        if (!product) {
            return res.status(404).json({ message: "❌ Product not found" });
        }

        res.json(product);
    } catch (error) {
        console.error("❌ Error fetching product details:", error);
        res.status(500).json({ message: "❌ Server error" });
    }
});


// Start Server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
