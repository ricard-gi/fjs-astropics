import express from 'express';
import cors from 'cors'; // cross-origin
import bcrypt from 'bcryptjs'; // encrypt
import { v4 as uuid } from 'uuid';
import multer from 'multer'; // file upload
import fs from 'fs'; // file i/o
import path from 'path';
import sharp from 'sharp'; // image editing
import jwt from 'jsonwebtoken'; // Importa la llibreria jsonwebtoken per a generar i verificar JWT

//import { handler as ssrHandler } from '../astro/dist/server/entry.mjs';

import * as url from 'url';
const __filename = url.fileURLToPath(import.meta.url);
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const SECRET_KEY = "vols-que-et-punxi-amb-un-punxo"; // to be used in jsonwebtoken creation

const app = express();
app.use(express.json());
app.use(cors());

const usersFile = 'data/users.json';
const imagesFolder = 'uploads';
const imagesFile = 'data/images.json';


// Funció per llegir els usuaris des del fitxer JSON
function readUsers() {
    const data = fs.readFileSync(usersFile);
    return JSON.parse(data);
}

// Funció per escriure els usuaris al fitxer JSON
function writeUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// Funció per llegir les imatges des del fitxer JSON
function readImages() {
    const data = fs.readFileSync(imagesFile);
    return JSON.parse(data);
}

// Funció per escriure les imatges al fitxer JSON
function writeImages(data) {
    fs.writeFileSync(imagesFile, JSON.stringify(data, null, 2));
}


// Middleware per verificar el JWT en la cookie
const checkToken = (req, res, next) => {
    let token = req.cookies?.token;// Obté el token des de la cookie de la petició 
    if (!token) token = req.headers['authorization']?.split(' ')[1]; //obté token de bearer auth

    //console.log('token', JSON.stringify(token))

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' }); // Retorna error 401 si no hi ha cap token
    }
    try {
        const decodedToken = jwt.verify(token, SECRET_KEY); // Verifica el token utilitzant la clau secreta
        req.userId = decodedToken.userId; // Estableix l'ID d'usuari a l'objecte de la petició
        req.userName = decodedToken.userName; // Estableix l'ID d'usuari a l'objecte de la petició
        next(); // Passa al següent middleware
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' }); // Retorna error 401 si el token és invàlid
    }
};


// LOGIN
// Endpoint per iniciar sessió d'un usuari

app.post('/api/login', (req, res) => {
    const { name, password } = req.body;
    const users = readUsers();

    const user = users.find(user => user.name === name);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Invalid name or password' });
    }

    const token = jwt.sign({ userId: user.id, userName: user.name }, SECRET_KEY, { expiresIn: '2h' }); // Genera un token JWT vàlid durant 2 hores
    res.cookie('token', token, { httpOnly: false, maxAge: 7200000 }); // Estableix el token com una cookie

    res.json({ message: 'Login successful', userId: user.id, name: user.name, token });
});


// REFRESH verifica si token és vàlid
app.get('/api/refresh', checkToken, async (req, res) => {
    const users = readUsers();


    const user = users.find(user => user.id === req.userId);
    if (!user ) {
        return res.status(401).json({ error: 'User not found' });
    }

    return res.json({ id: user.id, name: user.name })
})

// retorna usuaris
app.get('/api/users', checkToken, async (req, res) => {
    const users = readUsers();
    return res.json(users)
})

// retorna usuaris
app.get('/api/users/:userId', checkToken, async (req, res) => {
    const user = users.find(user => user.id === req.userId);
    if (!user ) {
        return res.status(401).json({ error: 'User not found' });
    }
    return res.json(user)
})



// Funció per registrar un nou usuari
app.post('/api/register', (req, res) => {
    const { name, password } = req.body;
    const users = readUsers();

    // Comprovar si l'name ja està en ús
    if (users.find(user => user.name === name)) {
        return res.status(400).json({ error: 'Name already exists' });
    }

    const id = uuid();
    const newUser = { id, name, password: bcrypt.hashSync(password, 8) };

    const token = jwt.sign({ userId: newUser.id, userName: newUser.name }, SECRET_KEY, { expiresIn: '2h' }); // Genera un token JWT vàlid durant 2 hores

    users.push(newUser);
    writeUsers(users);
    res.json({ message: 'User registered successfully', id, name, token });
});


// Configuració de multer per gestionar la pujada de fitxers
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'tmp') // Especifica la carpeta de destinació dels fitxers pujats
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}_${file.originalname}`) // Assigna un nom únic als fitxers pujats
    }
})

const upload = multer({ storage: storage }); // Configura multer per a gestionar la pujada d'un únic fitxer amb el camp 'foto'

// Funció per pujar una imatge amb hashtags
app.post('/api/upload', checkToken, upload.single('file'), async (req, res) => {
    const { hashtags } = req.body;
    const image = req.file;

    // Redimensionar la imatge abans de desar-la
    try {
        await sharp(image.path)
            .resize({ width: 800 })
            .toFile(`${imagesFolder}/${image.filename}`)
            .then(async () => {
                // Eliminar la imatge original després de redimensionar-la i desar-la
                await fs.unlink(image.path, () => { });
            });

    } catch (error) {
        //throw error
        return res.status(500).json({ error: 'Failed to process image xx' });
    }

    // req.userId='a5e876e1-6055-47f5-b532-383ee62a0fb5'
    // req.userName='ricard'

    // Guardar la informació de la imatge al fitxer images.json
    const images = readImages();
    images.unshift({ userName: req.userName, userId: req.userId, image: image.filename, hashtags, timestamp: new Date().getTime() });
    fs.writeFileSync(imagesFile, JSON.stringify(images, null, 2));

    res.json({ message: 'Image uploaded successfully' });
});




// Endpoint per obtenir les imatges d'un usuari
app.get('/api/images', checkToken, (req, res) => {
    const userId = req.userId;
    const userImages = readImages().filter(image => image.userId === userId);
    res.json(userImages);
});

app.get('/api/allimages', (req, res) => {
    res.json(readImages());
});


// Endpoint per obtenir les imatges d'un usuari
app.get('/api/user/:userId/images', checkToken, (req, res) => {
    const userId = req.params.userId;
    const userImages = readImages().filter(image => image.userId === userId);
    res.json(userImages);
});

// Endpoint per obtenir les imatges per hashtag
app.get('/api/images/hashtag/:hashtag', checkToken, (req, res) => {
    const hashtag = req.params.hashtag;
    const hashtagImages = readImages().filter(image => (image.hashtags+' ').includes('#'+hashtag+' '));
    res.json(hashtagImages);
});

// Endpoint per obtenir les imatges per hashtag
app.get('/api/images/user/:name', checkToken, (req, res) => {
    const name = req.params.name;
    const nameImages = readImages().filter(image => image.userName==name);
    res.json(nameImages);
});

// Endpoint per eliminar les imatges per nom
app.delete('/api/images/:imagename', checkToken, (req, res) => {
    const imagename = req.params.imagename;
    const nameImages = readImages().filter(image => image.image==!imagename);
    res.json(nameImages);
});


// REFRESH verifica si token és vàlid
app.delete('/api/users/:name', checkToken, async (req, res) => {
    try{
        const name = req.params.name;
        const nameImages = readImages().filter(image => image.userName!==name);
        writeImages(nameImages)
        const users = readUsers().filter(usr => usr.name!==name)
        writeUsers(users)
        res.json({'message': `usuari ${name} eliminat`});
    } catch (err) {
        res.status(500).json({'error': 'error eliminant usuari'})
    }

})

//Crear ruta estàtica per servir imatges a /uploads
app.use('/img', express.static(path.join(__dirname, 'uploads')));

/*
const base = '/';
app.use(base, express.static('../astro/dist/client/'));
app.use(ssrHandler);
*/

app.get('/', (req,res)=>{
    res.end("astropics api")
})


// Inicialitzar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
