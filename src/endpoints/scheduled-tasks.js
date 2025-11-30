import express from 'express';
import { requireAdminMiddleware } from '../users.js';
import scheduledTasksManager from '../scheduled-tasks.js';

export const router = express.Router();

/**
 * 获取定时任务配置
 */
router.get('/config', requireAdminMiddleware, async (request, response) => {
    try {
        const config = scheduledTasksManager.getTaskConfig();
        const status = scheduledTasksManager.getTaskStatus('clearAllBackups');

        return response.json({
            success: true,
            config: config || {
                enabled: false,
                cronExpression: '',
            },
            status: status || {
                enabled: false,
                running: false,
            },
        });
    } catch (error) {
        console.error('Get scheduled task config failed:', error);
        return response.status(500).json({ error: '获取定时任务配置失败: ' + error.message });
    }
});

/**
 * 保存定时任务配置
 */
router.post('/config', requireAdminMiddleware, async (request, response) => {
    try {
        const { enabled, cronExpression } = request.body;

        if (enabled && !cronExpression) {
            return response.status(400).json({ error: '启用定时任务时必须提供cron表达式' });
        }

        // 如果启用，验证cron表达式
        if (enabled) {
            const cron = await import('node-cron');
            if (!cron.default.validate(cronExpression)) {
                return response.status(400).json({ error: '无效的cron表达式' });
            }
        }

        // 保存配置
        const saved = scheduledTasksManager.saveTaskConfig({
            enabled: enabled || false,
            cronExpression: cronExpression || '',
        });

        if (!saved) {
            return response.status(500).json({ error: '保存配置失败' });
        }

        // 如果启用，启动任务；如果禁用，停止任务
        if (enabled) {
            const started = scheduledTasksManager.startClearAllBackupsTask(cronExpression);
            if (!started) {
                return response.status(500).json({ error: '启动定时任务失败' });
            }
        } else {
            scheduledTasksManager.stopTask('clearAllBackups');
        }

        return response.json({
            success: true,
            message: enabled ? '定时任务已启用' : '定时任务已禁用',
        });
    } catch (error) {
        console.error('Save scheduled task config failed:', error);
        return response.status(500).json({ error: '保存定时任务配置失败: ' + error.message });
    }
});

/**
 * 获取定时任务状态
 */
router.get('/status', requireAdminMiddleware, async (request, response) => {
    try {
        const status = scheduledTasksManager.getAllTasksStatus();
        return response.json({
            success: true,
            tasks: status,
        });
    } catch (error) {
        console.error('Get scheduled tasks status failed:', error);
        return response.status(500).json({ error: '获取定时任务状态失败: ' + error.message });
    }
});

/**
 * 手动执行清理所有备份文件任务（用于测试）
 */
router.post('/execute/clear-all-backups', requireAdminMiddleware, async (request, response) => {
    try {
        // 在后台执行，不阻塞响应
        scheduledTasksManager.executeClearAllBackups().catch(error => {
            console.error('手动执行清理备份任务失败:', error);
        });

        return response.json({
            success: true,
            message: '清理任务已开始执行，请查看服务器日志了解详情',
        });
    } catch (error) {
        console.error('Execute clear all backups task failed:', error);
        return response.status(500).json({ error: '执行清理任务失败: ' + error.message });
    }
});

