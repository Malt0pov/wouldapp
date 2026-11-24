const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getStatus: () => ipcRenderer.invoke('get-status'),
  connect: (payload) => ipcRenderer.invoke('connect', payload),
  disconnect: () => ipcRenderer.invoke('disconnect'),
  parse: (payload) => ipcRenderer.invoke('parse', payload),
  ping: (payload) => ipcRenderer.invoke('ping', payload),
  checkIp: () => ipcRenderer.invoke('check-ip'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  getServers: () => ipcRenderer.invoke('get-servers'),
  saveServers: (payload) => ipcRenderer.invoke('save-servers', payload),
  minimizeWindow: () => ipcRenderer.invoke('window-minimize'),
  closeWindow: () => ipcRenderer.invoke('window-close')
});
