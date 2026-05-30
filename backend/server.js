const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { sequelize, User, EngineerProfile, DraftProfile, Project, FloorZone, TaskHistoryLog, Setting } = require('./models');

try {
  require('dotenv').config();
} catch (e) {
  // Silent catch if dotenv is not installed yet
}

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'syncdraft-super-secret-key-123456';

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));
app.options('*', cors());
//app.use(cors());
app.use(express.json());

// ==================== CRYPTO & AUTH HELPERS ====================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === storedHash;
}

function generateToken(user) {
  const payload = JSON.stringify({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    exp: Date.now() + 24 * 60 * 60 * 1000 // 24 hours validity
  });
  const cipher = crypto.createCipheriv('aes-256-cbc', crypto.scryptSync(JWT_SECRET, 'salt', 32), Buffer.alloc(16, 0));
  let encrypted = cipher.update(payload, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function verifyToken(token) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.scryptSync(JWT_SECRET, 'salt', 32), Buffer.alloc(16, 0));
    let decrypted = decipher.update(token, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    const data = JSON.parse(decrypted);
    if (data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// ==================== AUTH MIDDLEWARES ====================

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
  req.user = decoded;
  next();
}

function requireAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    next();
  });
}

// Helper to calculate Dynamic Delay Risk
function getDelayRisk(floorZone, warningDays = 2) {
  if (floorZone.status === 'มีแบบ Shop แล้ว' || floorZone.status === 'ออกของแล้ว') {
    return 'Normal';
  }
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const deadline = new Date(floorZone.deadline);
  deadline.setHours(0, 0, 0, 0);

  if (today > deadline) {
    return 'OVERDUE';
  }

  const diffTime = deadline - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  if (diffDays <= warningDays) {
    return 'RISK';
  }

  return 'Normal';
}

// Get workload settings helper
async function getWorkloadSettings() {
  const settings = await Setting.findAll();
  const settingsMap = settings.reduce((acc, s) => {
    acc[s.key] = s.value;
    return acc;
  }, {});

  return {
    hoursPerSheet: parseFloat(settingsMap.hoursPerSheet || '1.5'),
    maxSheetsThreshold: parseInt(settingsMap.maxSheetsThreshold || '5'),
    warningDaysThreshold: parseInt(settingsMap.warningDaysThreshold || '2')
  };
}

// ==================== API ROUTES ====================

// 1. POST /api/auth/login - Authentication Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }

    const isValid = verifyPassword(password, user.salt, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }

    const token = generateToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. GET /api/settings - Fetch current workload config (Public/Authenticated)
app.get('/api/settings', async (req, res) => {
  try {
    const config = await getWorkloadSettings();
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. PUT /api/settings - Update workload config (Admin Only)
app.put('/api/settings', requireAdmin, async (req, res) => {
  try {
    const { hoursPerSheet, maxSheetsThreshold, warningDaysThreshold } = req.body;

    if (hoursPerSheet !== undefined) {
      await Setting.upsert({ key: 'hoursPerSheet', value: String(hoursPerSheet) });
    }
    if (maxSheetsThreshold !== undefined) {
      await Setting.upsert({ key: 'maxSheetsThreshold', value: String(maxSheetsThreshold) });
    }
    if (warningDaysThreshold !== undefined) {
      await Setting.upsert({ key: 'warningDaysThreshold', value: String(warningDaysThreshold) });
    }

    const updated = await getWorkloadSettings();
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 4. GET /api/users - Get all users (Authenticated)
app.get('/api/users', authenticate, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'name', 'email', 'role'],
      include: [
        { model: EngineerProfile, as: 'engineerProfile' },
        { model: DraftProfile, as: 'draftProfile' }
      ]
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. GET /api/dashboard - Summary analytics & workload matrices (Authenticated)
app.get('/api/dashboard', authenticate, async (req, res) => {
  try {
    const config = await getWorkloadSettings();
    const projects = await Project.findAll({
      include: [{ model: FloorZone, as: 'floorZones', where: { isDeleted: false }, required: false }]
    });

    // KPI Counts
    let totalFloors = 0;
    let activeFloors = 0;
    let overdueFloors = 0;
    let completedFloors = 0;

    projects.forEach(proj => {
      if (!proj.isArchived && proj.floorZones) {
        proj.floorZones.forEach(fz => {
          totalFloors++;
          const risk = getDelayRisk(fz, config.warningDaysThreshold);
          if (fz.status === 'มีแบบ Shop แล้ว' || fz.status === 'ออกของแล้ว') {
            completedFloors++;
          } else {
            activeFloors++;
            if (risk === 'OVERDUE') {
              overdueFloors++;
            }
          }
        });
      }
    });

    const engineers = await User.findAll({ where: { role: 'engineer' } });
    const drafts = await User.findAll({ where: { role: 'draft' }, include: [{ model: DraftProfile, as: 'draftProfile' }] });

    // Draft Workloads
    const draftWorkloads = drafts.map(draft => {
      const draftProjects = projects.filter(p => p.draftId === draft.id && !p.isArchived);
      const draftFloors = [];
      draftProjects.forEach(p => {
        if (p.floorZones) draftFloors.push(...p.floorZones.filter(fz => !fz.isDeleted));
      });

      const activeList = draftFloors.filter(fz => fz.status !== 'มีแบบ Shop แล้ว' && fz.status !== 'ออกของแล้ว');
      const completedList = draftFloors.filter(fz => fz.status === 'มีแบบ Shop แล้ว' || fz.status === 'ออกของแล้ว');
      const activeSheetsCount = activeList.reduce((sum, fz) => sum + fz.sheetCount, 0);
      const totalEstimatedHours = activeSheetsCount * config.hoursPerSheet;
      const overdueListCount = activeList.filter(fz => getDelayRisk(fz, config.warningDaysThreshold) === 'OVERDUE').length;

      return {
        id: draft.id,
        name: draft.name,
        email: draft.email,
        totalFloors: draftFloors.length,
        activeFloors: activeList.length,
        completedFloors: completedList.length,
        activeSheets: activeSheetsCount,
        estimatedHours: parseFloat(totalEstimatedHours.toFixed(1)),
        overdueFloors: overdueListCount,
        avgDelay: draft.draftProfile ? draft.draftProfile.avgDelay : 0.0
      };
    });

    // Engineer Workloads
    const engineerWorkloads = engineers.map(eng => {
      const engProjects = projects.filter(p => p.engineerId === eng.id && !p.isArchived);
      const engFloors = [];
      engProjects.forEach(p => {
        if (p.floorZones) engFloors.push(...p.floorZones.filter(fz => !fz.isDeleted));
      });

      const activeList = engFloors.filter(fz => fz.status !== 'มีแบบ Shop แล้ว' && fz.status !== 'ออกของแล้ว');
      const completedList = engFloors.filter(fz => fz.status === 'มีแบบ Shop แล้ว' || fz.status === 'ออกของแล้ว');
      const activeSheetsCount = activeList.reduce((sum, fz) => sum + fz.sheetCount, 0);
      const overdueListCount = activeList.filter(fz => getDelayRisk(fz, config.warningDaysThreshold) === 'OVERDUE').length;

      return {
        id: eng.id,
        name: eng.name,
        email: eng.email,
        projectsCount: engProjects.length,
        totalFloors: engFloors.length,
        activeFloors: activeList.length,
        completedFloors: completedList.length,
        activeSheets: activeSheetsCount,
        overdueFloors: overdueListCount
      };
    });

    res.json({
      stats: {
        totalFloors,
        activeFloors,
        overdueFloors,
        completedFloors
      },
      draftWorkloads,
      engineerWorkloads
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. GET /api/projects - Get all active projects (Authenticated)
app.get('/api/projects', authenticate, async (req, res) => {
  try {
    const config = await getWorkloadSettings();
    const projects = await Project.findAll({
      where: { isArchived: false },
      include: [
        { model: User, as: 'engineer', attributes: ['id', 'name', 'email'] },
        { model: User, as: 'draft', attributes: ['id', 'name', 'email'] },
        { 
          model: FloorZone, 
          as: 'floorZones', 
          where: { isDeleted: false },
          required: false
        }
      ],
      order: [['id', 'DESC']]
    });

    const projectsWithRisk = projects.map(proj => {
      const plainProj = proj.get({ plain: true });
      if (plainProj.floorZones) {
        plainProj.floorZones = plainProj.floorZones.map(fz => {
          fz.delayRisk = getDelayRisk(fz, config.warningDaysThreshold);
          fz.estimatedHours = fz.sheetCount * config.hoursPerSheet;
          return fz;
        });
      }
      return plainProj;
    });

    res.json(projectsWithRisk);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. GET /api/projects/archived - Restoration desk loader (Authenticated)
app.get('/api/projects/archived', authenticate, async (req, res) => {
  try {
    const archivedProjects = await Project.findAll({
      where: { isArchived: true },
      include: [{ model: User, as: 'engineer', attributes: ['id', 'name'] }]
    });

    const softDeletedFloors = await FloorZone.findAll({
      where: { isDeleted: true },
      include: [{ 
        model: Project, 
        as: 'project', 
        include: [{ model: User, as: 'engineer', attributes: ['name'] }]
      }]
    });

    res.json({
      archivedProjects,
      softDeletedFloors
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. POST /api/projects - Create a new project (Authenticated)
app.post('/api/projects', authenticate, async (req, res) => {
  const transaction = await sequelize.transaction();
  try {
    const { projectNumber, projectName, engineerId, draftId, notes, floorZones } = req.body;
    
    // Default sheetCount is 1
    const project = await Project.create({ projectNumber, projectName, engineerId, draftId, notes }, { transaction });

    if (floorZones && floorZones.length > 0) {
      for (const fz of floorZones) {
        const createdFz = await FloorZone.create({
          projectId: project.id,
          name: fz.name,
          sheetCount: parseInt(fz.sheetCount) || 1, // Default 1
          deadline: fz.deadline,
          status: 'รอ Framing',
          notes: fz.notes
        }, { transaction });

        await TaskHistoryLog.create({
          floorZoneId: createdFz.id,
          oldStatus: null,
          newStatus: 'รอ Framing',
          changedByUserId: req.user.id
        }, { transaction });
      }
    }

    await transaction.commit();
    res.status(201).json(project);
  } catch (error) {
    await transaction.rollback();
    res.status(400).json({ error: error.message });
  }
});

// 9. POST /api/projects/:id/floor-zones - Add inline floor zone (Authenticated)
app.post('/api/projects/:id/floor-zones', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, sheetCount, deadline, notes } = req.body;

    const createdFz = await FloorZone.create({
      projectId: parseInt(id),
      name,
      sheetCount: parseInt(sheetCount) || 1, // Default 1
      deadline,
      status: 'รอ Framing',
      notes
    });

    await TaskHistoryLog.create({
      floorZoneId: createdFz.id,
      oldStatus: null,
      newStatus: 'รอ Framing',
      changedByUserId: req.user.id
    });

    res.status(201).json(createdFz);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 10. PUT /api/floor-zones/:id/delete - Soft delete floor (Authenticated)
app.put('/api/floor-zones/:id/delete', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { isDeleted } = req.body;
    const fz = await FloorZone.findByPk(id);

    if (!fz) return res.status(404).json({ error: 'Floor not found' });

    await fz.update({ isDeleted: isDeleted !== undefined ? isDeleted : true });

    await TaskHistoryLog.create({
      floorZoneId: fz.id,
      oldStatus: fz.status,
      newStatus: isDeleted ? 'SOFT_DELETED' : 'RESTORED',
      changedByUserId: req.user.id
    });

    res.json(fz);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 11. POST /api/floor-zones/:id/split - Split a Floor/Zone (Authenticated)
app.post('/api/floor-zones/:id/split', authenticate, async (req, res) => {
  const transaction = await sequelize.transaction();
  try {
    const { id } = req.params;
    const { newZoneSuffix, splitSheetsCount } = req.body;

    const originalFloor = await FloorZone.findByPk(id, { transaction });
    if (!originalFloor) {
      return res.status(404).json({ error: 'Original Floor not found' });
    }

    const currentSheets = originalFloor.sheetCount;
    if (splitSheetsCount >= currentSheets) {
      return res.status(400).json({ error: 'Cannot split more sheets than currently available.' });
    }

    await originalFloor.update({
      sheetCount: currentSheets - splitSheetsCount
    }, { transaction });

    const splitFloor = await FloorZone.create({
      projectId: originalFloor.projectId,
      name: `${originalFloor.name} - ${newZoneSuffix || 'Zone B'}`,
      sheetCount: splitSheetsCount,
      deadline: originalFloor.deadline,
      status: originalFloor.status,
      notes: `Split from ${originalFloor.name}`
    }, { transaction });

    await TaskHistoryLog.create({
      floorZoneId: splitFloor.id,
      oldStatus: null,
      newStatus: originalFloor.status,
      changedByUserId: req.user.id
    }, { transaction });

    await transaction.commit();
    res.status(201).json({ original: originalFloor, split: splitFloor });
  } catch (error) {
    await transaction.rollback();
    res.status(400).json({ error: error.message });
  }
});

// 12. PUT /api/projects/:id/archive - Archive/Close project (Authenticated)
app.put('/api/projects/:id/archive', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { isArchived } = req.body;
    const project = await Project.findByPk(id);

    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    await project.update({ isArchived: isArchived !== undefined ? isArchived : true });
    res.json(project);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 13. PUT /api/floor-zones/:id - Modify floor details or status (Authenticated)
app.put('/api/floor-zones/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const floorZone = await FloorZone.findByPk(id);

    if (!floorZone) {
      return res.status(404).json({ error: 'Floor/Zone not found' });
    }

    const oldStatus = floorZone.status;
    const { name, sheetCount, deadline, status, notes } = req.body;

    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (sheetCount !== undefined) updateData.sheetCount = parseInt(sheetCount);
    if (deadline !== undefined) updateData.deadline = deadline;
    if (status !== undefined) updateData.status = status;
    if (notes !== undefined) updateData.notes = notes;

    await floorZone.update(updateData);

    if (status && status !== oldStatus) {
      await TaskHistoryLog.create({
        floorZoneId: floorZone.id,
        oldStatus: oldStatus,
        newStatus: status,
        changedByUserId: req.user.id
      });
    }

    res.json(floorZone);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// 14. GET /api/floor-zones/:id/history - Floor history logs (Authenticated)
app.get('/api/floor-zones/:id/history', authenticate, async (req, res) => {
  try {
    const logs = await TaskHistoryLog.findAll({
      where: { floorZoneId: req.params.id },
      include: [{ model: User, as: 'changedByUser', attributes: ['id', 'name', 'role'] }],
      order: [['timestamp', 'DESC']]
    });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DELETE PROJECT (Admin & Owning Engineer Only) ====================

app.delete('/api/projects/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const project = await Project.findByPk(id);

    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Access control: Admin OR the engineer who created the project
    if (req.user.role !== 'admin' && req.user.id !== project.engineerId) {
      return res.status(403).json({ error: 'Forbidden: You do not have permission to delete this project.' });
    }

    // Cascade delete is handled by database associations, but we enforce here
    await project.destroy();
    res.json({ message: `Project ${id} and all its floor zones and log trails deleted successfully.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN BACK-OFFICE USER CRUD ====================

// 1. GET /api/admin/users - Get all users with all attributes (Admin Only)
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'name', 'email', 'role']
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. POST /api/admin/users - Create User (Admin Only)
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const transaction = await sequelize.transaction();
  try {
    const { name, email, role, password } = req.body;
    if (!name || !email || !role || !password) {
      return res.status(400).json({ error: 'Please supply all user parameters (name, email, role, password).' });
    }

    // Check duplicate email
    const existing = await User.findOne({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'User with this email already exists.' });
    }

    const { salt, hash } = hashPassword(password);
    const user = await User.create({
      name,
      email,
      role,
      passwordHash: hash,
      salt
    }, { transaction });

    // Seed profile based on role
    if (role === 'engineer') {
      await EngineerProfile.create({ userId: user.id, avgDelay: 0 }, { transaction });
    } else if (role === 'draft') {
      await DraftProfile.create({ userId: user.id, avgDelay: 0 }, { transaction });
    }

    await transaction.commit();
    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    await transaction.rollback();
    res.status(400).json({ error: error.message });
  }
});

// 3. PUT /api/admin/users/:id - Update User details & Reset Password (Admin Only)
app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const transaction = await sequelize.transaction();
  try {
    const { id } = req.params;
    const { name, email, role, password } = req.body;
    const user = await User.findByPk(id, { transaction });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const oldRole = user.role;
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email;
    
    if (role !== undefined && role !== oldRole) {
      updateData.role = role;
      
      // Clean up previous profile & build new one
      if (oldRole === 'engineer') {
        await EngineerProfile.destroy({ where: { userId: user.id }, transaction });
      } else if (oldRole === 'draft') {
        await DraftProfile.destroy({ where: { userId: user.id }, transaction });
      }

      if (role === 'engineer') {
        await EngineerProfile.create({ userId: user.id, avgDelay: 0 }, { transaction });
      } else if (role === 'draft') {
        await DraftProfile.create({ userId: user.id, avgDelay: 0 }, { transaction });
      }
    }

    // Password reset capability
    if (password) {
      const { salt, hash } = hashPassword(password);
      updateData.passwordHash = hash;
      updateData.salt = salt;
    }

    await user.update(updateData, { transaction });
    await transaction.commit();

    res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    await transaction.rollback();
    res.status(400).json({ error: error.message });
  }
});

// 4. DELETE /api/admin/users/:id - Secure Delete User (Admin Only)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const transaction = await sequelize.transaction();
  try {
    const { id } = req.params;
    const user = await User.findByPk(id, { transaction });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Do not delete last admin
    if (user.role === 'admin') {
      const adminCount = await User.count({ where: { role: 'admin' }, transaction });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Cannot delete the final administrator user.' });
      }
    }

    // Cascade remove profiles
    if (user.role === 'engineer') {
      await EngineerProfile.destroy({ where: { userId: user.id }, transaction });
    } else if (user.role === 'draft') {
      await DraftProfile.destroy({ where: { userId: user.id }, transaction });
    }

    await user.destroy({ transaction });
    await transaction.commit();

    res.json({ message: `User ${id} has been deleted from SyncDraft database.` });
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({ error: error.message });
  }
});

// ==================== APP BOOTSTRAP ====================

sequelize.sync().then(() => {
  app.listen(PORT, () => {
    console.log(`SyncDraft production-ready backend listening at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Unable to sync db & start server:', err);
});
