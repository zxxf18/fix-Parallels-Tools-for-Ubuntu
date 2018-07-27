///////////////////////////////////////////////////////////////////////////////
//
// @file extension.js
//
// Parallels Coherence GhomeShell tracker.
//
// @author Dmitry Zhuk (dzhuk@parallels.com)
//
// Copyright (c) 2005-2017 Parallels Software International, Inc.
// All rights reserved.
// http://www.parallels.com
//
///////////////////////////////////////////////////////////////////////////////

const Main = imports.ui.main;
const St = imports.gi.St;
const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const Lang = imports.lang;
const Meta = imports.gi.Meta
const Wnck = imports.gi.Wnck
const Workspace = imports.ui.workspace;
const WorkspacesView = imports.ui.workspacesView;
const PopupMenu = imports.ui.popupMenu;
const Panel = imports.ui.panel;
const SwitcherPopup = imports.ui.switcherPopup;
const ModalDialog = imports.ui.modalDialog;
const ScreenShield = imports.ui.screenShield;
const ExtensionSystem = imports.ui.extensionSystem;
const ExtensionUtils = imports.misc.extensionUtils;

const PRL_PFX = 'Coherence: ';

let coherenceSetup = null;
let coherence = null;
let tracker = null;

function injectToFunction(prototype, name, func)
{
	let origin = prototype[name];
	prototype[name] = function()
	{
		let ret;
		ret = origin.apply(this, arguments);
		func.apply(this, arguments);
		return ret;
	}
	return origin;
}

function removeInjection(prototype, injection, name)
{
	if (injection[name] === undefined)
		delete prototype[name];
	else
		prototype[name] = injection[name];
}

const PRL_COHERENCE_WINDOW_FLAG_RESIZABLE = 1;
const PRL_COHERENCE_WINDOW_FLAG_EXTRAINPUT = 2;
const PRL_COHERENCE_WINDOW_FLAG_ACTIVATE = 4;

const coherenceProxyInterfaceXML = '\
<node> \
<interface name="com.parallels.prlcc.Coherence"> \
<method name="UpdateWindow"> \
 <arg type="i" name="id" direction="in"/> \
 <arg type="s" name="name" direction="in"/> \
 <arg type="i" name="type" direction="in"/> \
 <arg type="i" name="xid" direction="in"/> \
 <arg type="i" name="x" direction="in"/> \
 <arg type="i" name="y" direction="in"/> \
 <arg type="i" name="width" direction="in"/> \
 <arg type="i" name="height" direction="in"/> \
 <arg type="u" name="flagsMask" direction="in"/> \
 <arg type="u" name="flags" direction="in"/> \
 <arg type="a(iiii)" name="clipRects" direction="in"/> \
 <arg type="i" name="response" direction="out"/> \
</method> \
<method name="HideWindow"> \
 <arg type="i" name="id" direction="in"/> \
 <arg type="i" name="response" direction="out"/> \
</method> \
<method name="ExpoMode"> \
 <arg type="i" name="show" direction="in"/> \
 <arg type="i" name="response" direction="out"/> \
</method> \
</interface> \
</node> \
';

const CoherenceProxyInterface = Gio.DBusProxy.makeProxyWrapper(
	coherenceProxyInterfaceXML, this);

const CoherenceInterface = new Lang.Class
({
	Name: 'CoherenceInterface',

	_init: function()
	{
		this._proxy = null;
		this._reset();
		this._nextId = 0;
		this._ids = {};
		this._expoMode = false;
		this._lockMode = false;
		this._modalMode = false;
		this._lockWindowId = this.getNextId();
		this._modalWindowId = this.getNextId();
		this.activeWnckWindow = null;
	},

	destroy: function()
	{
		this._reset();
	},

	_reset: function()
	{
		this.setup('', '', '');
	},

	setup: function(name, path, iface)
	{
		let ret = 0;

		if (this._proxy)
		{
			log(PRL_PFX + 'Detaching interface "' + this._busIface + '"...');

			this._proxy.run_dispose();
			this._proxy = null;

			log(PRL_PFX + ' detached "' + this._busIface + '".');
		}

		this._busName = name;
		this._busPath = path;
		this._busIface = iface;

		if (name != '' && path != '' && iface == 'com.parallels.prlcc.Coherence')
		{
			log(PRL_PFX + 'Attaching interface "' + this._busIface + '"...');
			log(PRL_PFX + 'Setup {'
				+ 'name="' + this._busName
				+ '", path="' + this._busPath
				+ '"}.');
			this._proxy = new CoherenceProxyInterface(
				Gio.DBus.session, name, path,
				Lang.bind(this,
					function(proxy, error)
					{
						if (error)
						{
							log('Error: ' + error);
						}
					})
				);
			log(PRL_PFX + ' attached ' + this._busIface + '.');
		}

		return ret;
	},

	_updateWindow: function(id, name, type, xid, x, y, width, height,
		flagsMask, flags, clipRects)
	{
		if (!this._proxy)
			return;
		try
		{
			this._proxy.UpdateWindowSync(id, name, type, xid, x, y, width, height,
				flagsMask, flags, clipRects);
		}
		catch (e)
		{
			log(PRL_PFX + 'Error: calling method UpdateWindow: ' + e);
			this._reset();
		}
	},

	modalMode: function(activate)
	{
		if (!this._proxy)
			return;

		if (this._modalMode == activate)
			return;

		let id = this._modalWindowId;
		if (activate)
		{
			let size = global.screen.get_size();
			this._updateWindow(id, 'Modal window', 0, 0, 0, 0, size[0], size[1], 0, 0, []);
		}
		else
			this.hideWindow(id, false);

		this._modalMode = activate;
	},

	lockMode: function(activate)
	{
		if (!this._proxy)
			return;

		if (this._lockMode == activate)
			return;

		let id = this._lockWindowId;
		if (activate)
		{
			let size = global.screen.get_size();
			this._updateWindow(id, 'Lock screen', 0, 0, 0, 0, size[0], size[1], 0, 0, []);
		}
		else
			this.hideWindow(id, false);

		this._lockMode = activate;
	},

	expoMode: function(show)
	{
		if (!this._proxy)
			return;
		try
		{
			let expoMode = show ? true : false;
			if (expoMode != this._expoMode)
			{
				this._expoMode = expoMode;
				this._proxy.ExpoModeSync(expoMode ? 1 : 0);
			}
		}
		catch (e)
		{
			log(PRL_PFX + 'Error: calling method ExpoMode: ' + e);
			this._reset();
		}
	},

	updateMetaWindow: function(metaWindow)
	{
		let id = metaWindow.coherenceId;
		let name = "n/a";
		let type = metaWindow.get_window_type();
		let xid = 0;
		let rect = metaWindow.get_frame_rect();
		let x = rect.x;
		let y = rect.y;
		let width = rect.width;
		let height = rect.height;
		this._updateWindow(id, name, type, xid, x, y, width, height, 0, 0, []);
	},

	updateWnckWindow: function(wnckWindow)
	{
		let activate = (this.activeWnckWindow == wnckWindow);
		let id = wnckWindow.coherenceId;
		let name = wnckWindow.get_name()
		let type = 0;
		let xid = wnckWindow.get_xid()
		let geom = wnckWindow.get_geometry();
		let x = geom[0];
		let y = geom[1]
		let width = geom[2];
		let height = geom[3];
		let flagsMask =	PRL_COHERENCE_WINDOW_FLAG_ACTIVATE
			| PRL_COHERENCE_WINDOW_FLAG_RESIZABLE
			| PRL_COHERENCE_WINDOW_FLAG_EXTRAINPUT;
		let flags = 0;
		let clipRects = [];
		if (activate)
			flags = flags | PRL_COHERENCE_WINDOW_FLAG_ACTIVATE;
		if (xid)
		{
			flags = flags | PRL_COHERENCE_WINDOW_FLAG_RESIZABLE | PRL_COHERENCE_WINDOW_FLAG_EXTRAINPUT;
			let margins = [ 5, 5, 5, 5 ];
			clipRects.push([ x - margins[0], y - margins[1], x + width + margins[2], y + height + margins[3] ]);
		}
		this._updateWindow(id, name, type, xid, x, y, width, height, flagsMask, flags, clipRects);
	},

	updatePopupMenu: function(popupMenu, lastUpdateGeom)
	{
		let id = popupMenu.coherenceId;
		let name = 'n/a';
		let type = 0;
		let xid = 0;
		let clutterActor = popupMenu.box;

		let pos = clutterActor.get_transformed_position();
		let size = clutterActor.get_transformed_size();

		let x = pos[0];
		let y = pos[1];
		let width = size[0];
		let height = size[1];

		if (Math.abs(lastUpdateGeom[0] - x) > 0.5
				|| Math.abs(lastUpdateGeom[1] - y) > 0.5
				|| Math.abs(lastUpdateGeom[2] - width) > 0.5
				|| Math.abs(lastUpdateGeom[3] - height) > 0.5)
		{
			this._updateWindow(id, name, type, xid, x, y, width, height, 0, 0, []);
			return [x, y, width, height];
		}
		return lastUpdateGeom;
	},

	updatePanel: function(panel, main, lastUpdateGeom)
	{
		let id = panel.coherenceId;
		let name = main ? 'Main Panel' : 'n/a';
		let type = 0;
		let xid = 0;
		let clutterActor = panel.actor;

		let pos = clutterActor.get_transformed_position();
		let size = clutterActor.get_transformed_size();

		let x = pos[0];
		let y = pos[1];
		let width = size[0];
		let height = size[1];

		if (Math.abs(lastUpdateGeom[0] - x) > 0.5
				|| Math.abs(lastUpdateGeom[1] - y) > 0.5
				|| Math.abs(lastUpdateGeom[2] - width) > 0.5
				|| Math.abs(lastUpdateGeom[3] - height) > 0.5)
		{
			this._updateWindow(id, name, type, xid, x, y, width, height, 0, 0, []);
			return [x, y, width, height];
		}
		return lastUpdateGeom;
	},

	updateUIActor: function(uiActor)
	{
		let lastUpdateGeom = uiActor.lastUpdateGeom;
		let clutterActor = uiActor._clutterActor;
		let id = clutterActor.coherenceId;
		let name = 'n/a';
		let type = 0;
		let xid = 0;

		let pos = clutterActor.get_transformed_position();
		let size = clutterActor.get_transformed_size();

		let x = pos[0];
		let y = pos[1];
		let width = size[0];
		let height = size[1];

		if (Math.abs(lastUpdateGeom[0] - x) > 0.5
				|| Math.abs(lastUpdateGeom[1] - y) > 0.5
				|| Math.abs(lastUpdateGeom[2] - width) > 0.5
				|| Math.abs(lastUpdateGeom[3] - height) > 0.5)
		{
			this._updateWindow(id, name, type, xid, x, y, width, height, 0, 0, []);
			return [x, y, width, height];
		}
		this.lastUpdateGeom = lastUpdateGeom;
		return this.lastUpdateGeom;
	},

	hideWindow: function(id, removeId = true)
	{
		if (id == undefined)
			return;

		if (removeId)
		{
			this._ids[id] = undefined;
			if (this._ids[this._nextId] != undefined || id < this._nextId)
				this._nextId = id;
		}

		if (!this._proxy)
			return;
		try
		{
			this._proxy.HideWindowSync(id);
		}
		catch (e)
		{
			log(PRL_PFX + 'Error: calling method HideWindow: ' + e);
			this._reset();
		}
	},

	getNextId: function()
	{
		let id = this._nextId;
		while (this._ids[id] != undefined)
			id = id + 1;
		this._nextId = id + 1;
		this._ids[id] = id;
		return id;
	},
});

const coherenceSetupInterfaceName = 'com.parallels.gnome.CoherenceSetup';

const coherenceSetupInterfaceXML = '\
<node> \
<interface name= \
"' + coherenceSetupInterfaceName + '" \
> \
<method name="SetupBus"> \
  <arg type="s" name="name" direction="in"/> \
  <arg type="s" name="path" direction="in"/> \
  <arg type="s" name="iface" direction="in"/> \
  <arg type="i" name="error" direction="out"/> \
</method> \
<method name="GetBusInfo"> \
  <arg type="s" name="name" direction="out"/> \
  <arg type="s" name="path" direction="out"/> \
  <arg type="s" name="iface" direction="out"/> \
</method> \
<method name="ActualizeWindows"> \
  <arg type="i" name="error" direction="out"/> \
</method> \
<signal name="InterfaceAvailable"> \
  <arg type="s" name="name"/> \
</signal> \
</interface> \
</node> \
';

const CoherenceSetupInterface = new Lang.Class
({
	Name: 'CoherenceSetupInterface',

	_init: function() {

		log(PRL_PFX + 'Registering interface "' + coherenceSetupInterfaceName + '"...');

		this._dbusImpl = Gio.DBusExportedObject.wrapJSObject(coherenceSetupInterfaceXML, this);
		this._dbusImpl.export(Gio.DBus.session, '/com/parallels/gnome');

		this._busName = "";
		this._busPath = "";
		this._busIface = "";

		this._dbusImpl.emit_signal('InterfaceAvailable',
			GLib.Variant.new('(s)', [coherenceSetupInterfaceName]));

		log(PRL_PFX + ' registered "' + coherenceSetupInterfaceName + '".');
	},

	destroy: function()
	{
		log(PRL_PFX + 'Unregistering interface "' + coherenceSetupInterfaceName + '"...');

		this._dbusImpl.unexport();

		log(PRL_PFX + ' unregistered "' + coherenceSetupInterfaceName + '".');
	},

	SetupBus: function(name, path, iface)
	{
		this._busName = name;
		this._busPath = path;
		this._busIface = iface;

		coherence.setup(name, path, iface);

		return 0;
	},

	GetBusInfo: function()
	{
		let r = [];
		r.push(this._busName);
		r.push(this._busPath);
		r.push(this._busIface);
		return r;
	},

	ActualizeWindows: function()
	{
		tracker.actualizeWindows();
		return 0;
	},
});

const PrlMetaWindow = new Lang.Class
({
	Name: 'PrlMetaWindow',

	_init: function(prlTracker, metaWindow)
	{
		this._metaWindow = metaWindow;
		this._prlTracker = prlTracker;
		this._windowSignals = [];
		this._windowSignals.push(metaWindow.connect(
			'size-changed', Lang.bind(this, this._sizePosChanged)));
		this._windowSignals.push(metaWindow.connect(
			'position-changed', Lang.bind(this, this._sizePosChanged)));
		this._windowSignals.push(metaWindow.connect(
			'focus', Lang.bind(this, this._focus)));
	},

	destroy: function()
	{
		let metaWindow = this._metaWindow
		for (let i in this._windowSignals)
			metaWindow.disconnect(this._windowSignals[i]);
		coherence.hideWindow(metaWindow.coherenceId);
	},

	onMaped: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.updateMetaWindow(this._metaWindow);
	},

	_onFocused: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.updateMetaWindow(this._metaWindow);
	},

	_onGeomChanged: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.updateMetaWindow(this._metaWindow);
	},

	_focus: function(metaWindow)
	{
		if (!this._prlTracker.enabled)
			return;
		if (metaWindow != this._metaWindow)
			return;
		this._onFocused();
	},

	_sizePosChanged: function(metaWindow)
	{
		if (!this._prlTracker.enabled)
			return;
		if (metaWindow != this._metaWindow)
			return;
		this._onGeomChanged();
	},
});

const PrlMetaTracker = new Lang.Class
({
	Name: 'PrlMetaTracker',

	_init: function()
	{
		this._display = global.screen.get_display();
		this._shellwm = global.window_manager;

		this.resetInjections();

		this._displaySignals = [];
		this._shellWMSignals = [];
		this._windows = [];

		this.enabled = false;
	},

	destroy: function()
	{
	},

	resetInjections: function()
	{
	},

	_windowCreated: function(display, metaWindow, noRecurse)
	{
		if (!this.enabled)
			return;
		if (metaWindow.get_window_type() == Meta.WindowType.NORMAL)
			return;

		if (metaWindow.coherenceId == undefined)
			metaWindow.coherenceId = coherence.getNextId();

		let id = metaWindow.coherenceId;
		let winId = id.toString();

		let p = this._windows[winId];
		if (!p)
		{
			p = new PrlMetaWindow(this, metaWindow);
			this._windows[winId] = p;
		}
	},

	_mapWindow: function(shellwm, actor)
	{
		if (!this.enabled)
			return;
		let metaWindow = actor.get_meta_window();

		let id = metaWindow.coherenceId;
		if (id != undefined)
		{
			let winId = id.toString();
			let p = this._windows[winId];
			if (p)
				p.onMaped();
		}
	},

	_destroyWindow: function(shellwm, actor)
	{
		if (!this.enabled)
			return;
		let metaWindow = actor.get_meta_window();

		let id = metaWindow.coherenceId;
		if (id != undefined)
		{
			let winId = id.toString();
			let p = this._windows[winId];
			if (p)
			{
				p.destroy();
				delete this._windows[winId];
			}
		}
	},

	enable: function()
	{
		this.resetInjections();

		this._display = global.screen.get_display();

		this._displaySignals.push(this._display.connect_after(
			'window-created', Lang.bind(this, this._windowCreated)));
		this._shellWMSignals.push(this._shellwm.connect(
			'map', Lang.bind(this, this._mapWindow)));
		this._shellWMSignals.push(this._shellwm.connect(
			'destroy', Lang.bind(this, this._destroyWindow)));

		this.enabled = true;
	},

	disable: function()
	{
		for (let i in this._displaySignals)
			this._display.disconnect(this._displaySignals[i]);
		for (let i in this._shellWMSignals)
			this._shellwm.disconnect(this._shellWMSignals[i]);
		this._displaySignals = [];
		this._shellWMSignals = [];

		this.resetInjections();

		for (let i in this._windows)
		{
			let prlWindow = this._windows[i];
			prlWindow.destroy();
		}
		this._windows = [];
		
		this._enabled = false;
	},

	actualizeWindows: function()
	{
	},
});

const PrlWnckWindow = new Lang.Class
({
	Name: 'PrlWnckWindow',

	_init: function(prlTracker, wnckWindow)
	{
		this._wnckWindow = wnckWindow
		this._prlTracker = prlTracker;

		this._windowSignals = [];
		this._windowSignals.push(wnckWindow.connect(
			'geometry-changed', Lang.bind(this, this._geometryChanged)));
		this._windowSignals.push(wnckWindow.connect(
			'state-changed', Lang.bind(this, this._stateChanged)));

		this._workspaceId = 0;
	},

	destroy: function()
	{
		let wnckWindow = this._wnckWindow
		for (let i in this._windowSignals)
			wnckWindow.disconnect(this._windowSignals[i]);
		coherence.hideWindow(wnckWindow.coherenceId);
	},

	onMaped: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.updateWnckWindow(this._wnckWindow);
	},

	onFocused: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.activeWnckWindow = this._wnckWindow;
		coherence.updateWnckWindow(this._wnckWindow);
	},

	_onGeomChanged: function()
	{
		if (!this._prlTracker.enabled)
			return;
		coherence.updateWnckWindow(this._wnckWindow);
	},

	_geometryChanged: function(wnckWindow, user_data)
	{
		if (!this._prlTracker.enabled)
			return;
		if (wnckWindow != this._wnckWindow)
			return;
		this._onGeomChanged();
	},

	_stateChanged: function(wnckWindow, changed_mask, new_state, user_data)
	{
		if (!this._prlTracker.enabled)
			return;

		if (wnckWindow != this._wnckWindow)
			return;
		if (changed_mask & Wnck.WindowState.MINIMIZED)
		{
			if (new_state & Wnck.WindowState.MINIMIZED)
				coherence.hideWindow(wnckWindow.coherenceId, false);
			else
				coherence.updateWnckWindow(wnckWindow);
		}
	},
});

const PrlWnckTracker = new Lang.Class
({
	Name: 'PrlWnckTracker',

	_init: function()
	{
		this.enabled = false;

		this._wnckScreen = Wnck.Screen.get_default();

		this._windows = [];
		this._screenSignals = [];

		this._currentWorkspaceId = 0;
	},

	destroy: function()
	{
	},

	_windowOpened: function(wnckScreen, wnckWindow, user_data)
	{
		if (!this.enabled)
			return;

		if (wnckWindow.coherenceId == undefined)
			wnckWindow.coherenceId = coherence.getNextId();

		let state = wnckWindow.get_state();
		let id = wnckWindow.coherenceId;
		let winId = id.toString();

		let p = this._windows[winId];
		if (!p)
		{
			p = new PrlWnckWindow(this, wnckWindow);
			this._windows[winId] = p;
		}
		if (!(state & Wnck.WindowState.MINIMIZED))
			p.onMaped();
	},

	_windowClosed: function(wnckScreen, wnckWindow, user_data)
	{
		if (!this.enabled)
			return;

		let id = wnckWindow.coherenceId;
		if (id != undefined)
		{
			let winId = id.toString();
			let p = this._windows[winId];
			if (p)
			{
				p.destroy();
				delete this._windows[winId];
			}
			wnckWindow.coherenceId = undefined;
		}
	},

	_activeWindowChanged: function(wnckScreen, wnckWindowPrevActive, user_data)
	{
		if (!this.enabled)
			return;

		let wnckWindow = wnckScreen.get_active_window();

		let id = undefined;
		if (wnckWindow)
			id = wnckWindow.coherenceId;
		if (id != undefined)
		{
			let winId = id.toString();
			let p = this._windows[winId]
			if (p)
				p.onFocused();
		}
	},

	_activeWorkspaceChanged: function(wnckScreen, wnckWorkspacePrevActive)
	{
		if (!this.enabled)
			return;

		let wnckWorkspace = wnckScreen.get_active_workspace();
		this._currentWorkspaceId = wnckWorkspace.get_number();

		coherence.activeWnckWindow = null;

		this.actualizeWindows();
	},

	get currentWorkspaceId()
	{
		return this._currentWorkspaceId;
	},

	enable: function()
	{
		let wnckScreen = this._wnckScreen;

		this._screenSignals.push(wnckScreen.connect(
			'window-opened', Lang.bind(this, this._windowOpened)));
		this._screenSignals.push(wnckScreen.connect(
			'window-closed', Lang.bind(this, this._windowClosed)));
		this._screenSignals.push(wnckScreen.connect(
			'active-window-changed', Lang.bind(this, this._activeWindowChanged)));
		this._screenSignals.push(wnckScreen.connect_after(
			'active-workspace-changed', Lang.bind(this, this._activeWorkspaceChanged)));

		this.enabled = true;
	},

	disable: function()
	{
		let wnckScreen = this._wnckScreen;

		for (let i in this._screenSignals)
			wnckScreen.disconnect(this._screenSignals[i]);
		this._screenSignals = [];

		for (let i in this._windows)
		{
			let prlWindow = this._windows[i];
			prlWindow.destroy();
		}
		this._windows = [];

		coherence.activeWnckWindow = null;

		this._enabled = false;
	},

	actualizeWindows: function()
	{
		let wnckScreen = this._wnckScreen;
		let windows = wnckScreen.get_windows_stacked();

		for (let i in windows)
		{
			let wnckWindow = windows[i];
			let wnckWorkspace = wnckWindow.get_workspace();
			let workspaceId = wnckWorkspace.get_number();
			if (workspaceId == this._currentWorkspaceId)
			{
				this._windowOpened(wnckScreen, wnckWindow, null);
			}
			else
			{
				this._windowClosed(wnckScreen, wnckWindow, null);
			}
		}
	},
});

let uiPopupMenus = {};
let uiPanels = {};
let uiActors = {};

const PrlUIPopupMenu = new Lang.Class
({
	Name: 'PrlUIPopupMenu',

	_init: function(popupMenu)
	{
		let clutterActor = popupMenu.box;

		this._popupMenu = popupMenu;
		this._clutterActor = clutterActor;

		this.lastUpdateGeom = [0, 0, 0, 0];

		this._clutterSignals = [];
		this._clutterSignals.push(clutterActor.connect(
			'paint', Lang.bind(this, this._paint)));
	},

	destroy: function()
	{
		let popupMenu = this._popupMenu;
		let clutterActor = this._clutterActor;
		for (let i in this._clutterSignals)
			clutterActor.disconnect(this._clutterSignals[i]);
		this._clutterSignals = [];
		coherence.hideWindow(popupMenu.coherenceId);
	},

	_paint: function(clutterActor)
	{
		let popupMenu = this._popupMenu;
		if (clutterActor != this._clutterActor)
			return;
		this.lastUpdateGeom = coherence.updatePopupMenu(popupMenu, this.lastUpdateGeom);
	},
});

function onActorDestroy(clutterActor)
{
	let id = clutterActor.coherenceId;
	if (id != undefined)
	{
		let winId = id.toString();
		let p = uiActors[winId];
		if (p)
		{
			p.destroy();
			delete uiActors[winId];
		}
		clutterActor.coherenceId = undefined;
	}
}

const PrlUIActor = new Lang.Class
({
	Name: 'PrlUIActor',

	_init: function(clutterActor)
	{
		this._clutterActor = clutterActor;

		this.lastUpdateGeom = [0, 0, 0, 0];

		this._clutterSignals = [];
		this._clutterSignals.push(clutterActor.connect(
			'paint', Lang.bind(this, this._paint)));
		this._clutterSignals.push(clutterActor.connect(
			'destroy', onActorDestroy));
	},

	destroy: function()
	{
		let clutterActor = this._clutterActor;
		for (let i in this._clutterSignals)
			clutterActor.disconnect(this._clutterSignals[i]);
		this._clutterSignals = [];
		coherence.hideWindow(clutterActor.coherenceId);
	},

	_paint: function(clutterActor)
	{
		if (clutterActor != this._clutterActor)
			return;
		this.lastUpdateGeom = coherence.updateUIActor(this);
	},
});

const PrlUIPanel = new Lang.Class
({
	Name: 'PrlUIPanel',

	_init: function(panel, main)
	{
		let clutterActor = panel.actor;

		this._panel = panel;
		this._clutterActor = clutterActor;
		this._main = main;

		this.lastUpdateGeom = [0, 0, 0, 0];

		this._clutterSignals = [];
		this._clutterSignals.push(clutterActor.connect(
			'paint', Lang.bind(this, this._paint)));
	},

	destroy: function()
	{
		let panel = this._panel;
		let clutterActor = this._clutterActor;
		for (let i in this._clutterSignals)
			clutterActor.disconnect(this._clutterSignals[i]);
		this._clutterSignals = [];
		coherence.hideWindow(panel.coherenceId);
	},

	_paint: function(clutterActor)
	{
		let panel = this._panel;
		if (clutterActor != this._clutterActor)
			return;
		this.lastUpdateGeom = coherence.updatePanel(panel, this._main, this.lastUpdateGeom);
	},

	updateGeom: function()
	{
		let panel = this._panel;
		this.lastUpdateGeom = [0, 0, 0, 0];
		this.lastUpdateGeom = coherence.updatePanel(panel, this._main, this.lastUpdateGeom);
	},
});

const PRL_INJ_DASH_TO_DOCK = 'dash-to-dock@micxgx.gmail.com';
const PRL_INJ_WINDOW_LIST = 'window-list@gnome-shell-extensions.gcampax.github.com';

const PrlUITracker = new Lang.Class
({
	Name: 'PrlUITracker',

	_init: function()
	{
		this.enabled = false;

		this.resetInjections();

		uiPopupMenus = {};
		uiPanels = {};
		uiActors = {};

		ExtensionSystem.connect('extension-state-changed',
			Lang.bind(this, this._extensionStateChanged));
	},

	destroy: function()
	{
	},

	_extensionStateChanged: function(_, newState)
	{
		if (newState.state == ExtensionSystem.ExtensionState.ENABLED)
			this._injectExtension(newState.uuid);
		else
			this._uninjectExtension(newState.uuid);
	},

	resetInjections: function()
	{
		this._screenShieldInj = {};
		this._switcherListInj = {};
		this._popupMenuInj = {};
		this._modalDialogInj = {};
		this._workViewInj = {};

		this.Ext = {};
		this.Ext.MyDash = null;
		this.Ext._myDashInj = {};
		this.Ext.WindowList = null;
		this.Ext._winListInj = {};
	},

	_injectExtension: function(uuid)
	{
		let ext = ExtensionUtils.extensions[uuid];
		if (ext == undefined || ext.imports == undefined)
			return;

		this._uninjectExtension(uuid);

		if (uuid == PRL_INJ_DASH_TO_DOCK)
		{
			try
			{
				this.Ext.MyDash = ext.imports.dash.MyDash;
				this.Ext._myDashInj['_redisplay'] = injectToFunction(
					this.Ext.MyDash.prototype,
					'_redisplay',
					function()
					{
						let clutterActor = this._container;
						if (clutterActor.coherenceId == undefined)
							clutterActor.coherenceId = coherence.getNextId();
						let id = clutterActor.coherenceId;
						let winId = id.toString();
						let p = uiActors[winId];
						if (!p)
						{
							p = new PrlUIActor(clutterActor);
							uiActors[winId] = p;
						}
					});
				log(PRL_PFX + 'Class ' + this.Ext.MyDash.toString() + ' injected.');
			}
			catch(e)
			{
				this.Ext.MyDash = null;
				this.Ext._myDashInj = {};
				log(PRL_PFX + 'Can not inject ' + uuid + ' extension: ' + e.toString());
			}
		}
		else if (uuid == PRL_INJ_WINDOW_LIST)
		{
			try
			{
				this.Ext.WindowList = ext.imports.extension.WindowList;
				this.Ext._winListInj['_populateWindowList'] = injectToFunction(
					this.Ext.WindowList.prototype,
					'_populateWindowList',
					function()
					{
						let clutterActor = this.actor;
						if (clutterActor.coherenceId == undefined)
							clutterActor.coherenceId = coherence.getNextId();
						let id = clutterActor.coherenceId;
						let winId = id.toString();
						let p = uiActors[winId];
						if (!p)
						{
							p = new PrlUIActor(clutterActor);
							uiActors[winId] = p;
						}
					});
				log(PRL_PFX + 'Class ' + this.Ext.WindowList.toString() + ' injected.');
			}
			catch(e)
			{
				this.Ext.WindowList = null;
				this.Ext._winListInj = {};
				log(PRL_PFX + 'Can not inject ' + uuid + ' extension: ' + e.toString());
			}
		}
	},

	_uninjectExtension: function(uuid)
	{
		if (uuid == PRL_INJ_DASH_TO_DOCK)
		{
			for (let i in this.Ext._myDashInj)
				removeInjection(this.Ext.MyDash.prototype, this.Ext._myDashInj, i);
			this.Ext._myDashInj = {};
			if (this.Ext.MyDash)
				log(PRL_PFX + 'Uninjected ' + this.Ext.MyDash.toString() + ' class.');
			this.Ext.MyDash = null;
		}
		else if (uuid == PRL_INJ_WINDOW_LIST)
		{
			for (let i in this.Ext._winListInj)
				removeInjection(this.Ext.WindowList.prototype, this.Ext._winListInj, i);
			this.Ext._winListInj = {};
			if (this.Ext.WindowList)
				log(PRL_PFX + 'Uninjected ' + this.Ext.WindowList.toString() + ' class.');
			this.Ext.WindowList = null;
		}
	},

	_injectExtensions: function()
	{
		this._injectExtension(PRL_INJ_DASH_TO_DOCK);
		this._injectExtension(PRL_INJ_WINDOW_LIST);
	},

	_uninjectExtensions: function()
	{
		this._uninjectExtension(PRL_INJ_DASH_TO_DOCK);
		this._uninjectExtension(PRL_INJ_WINDOW_LIST);
	},

	enable: function()
	{
		this.resetInjections();

		this._popupMenuInj['open'] = injectToFunction(
			PopupMenu.PopupMenu.prototype,
			'open',
			function(animate)
			{
				if (this.coherenceId == undefined)
					this.coherenceId = coherence.getNextId();
				let id = this.coherenceId;
				let winId = id.toString();
				let p = uiPopupMenus[winId];
				if (!p)
				{
					p = new PrlUIPopupMenu(this);
					uiPopupMenus[winId] = p;
				}
			});
		this._popupMenuInj['close'] = injectToFunction(
			PopupMenu.PopupMenu.prototype,
			'close',
			function(animate)
			{
				let id = this.coherenceId;
				if (id != undefined)
				{
					let winId = id.toString();
					let p = uiPopupMenus[winId];
					if (p)
					{
						p.destroy();
						delete uiPopupMenus[winId];
					}
					this.coherenceId = undefined;
				}
			});

		this._switcherListInj['_init'] = injectToFunction(
			SwitcherPopup.SwitcherList.prototype,
			'_init',
			function()
			{
				let clutterActor = this.actor;
				if (clutterActor.coherenceId == undefined)
					clutterActor.coherenceId = coherence.getNextId();
				let id = clutterActor.coherenceId;
				let winId = id.toString();
				let p = uiActors[winId];
				if (!p)
				{
					p = new PrlUIActor(clutterActor);
					uiActors[winId] = p;
				}
			});

		this._workViewInj['_init'] = injectToFunction(
			WorkspacesView.WorkspacesView.prototype,
			'_init',
			function()
			{
				coherence.expoMode(true);
			});
		this._workViewInj['_onDestroy'] = injectToFunction(
			WorkspacesView.WorkspacesView.prototype,
			'_onDestroy',
			function()
			{
				coherence.expoMode(false);
			});

		this._modalDialogInj['open'] = injectToFunction(
			ModalDialog.ModalDialog.prototype,
			'open',
			function()
			{
				coherence.modalMode(true);
			});
		this._modalDialogInj['close'] = injectToFunction(
			ModalDialog.ModalDialog.prototype,
			'close',
			function()
			{
				coherence.modalMode(false);
			});

		this._screenShieldInj['activate'] = injectToFunction(
			ScreenShield.ScreenShield.prototype,
			'activate',
			function()
			{
				coherence.lockMode(true);
			});
		this._screenShieldInj['deactivate'] = injectToFunction(
			ScreenShield.ScreenShield.prototype,
			'deactivate',
			function()
			{
				coherence.lockMode(false);
			});

		this._injectExtensions();

		if (Main.panel.coherenceId == undefined)
			Main.panel.coherenceId = coherence.getNextId();
		let id = Main.panel.coherenceId;
		let winId = id.toString();
		let p = uiPanels[winId];
		if (!p)
		{
			p = new PrlUIPanel(Main.panel, true);
			uiPanels[winId] = p;
		}

		this.enabled = true;
	},

	disable: function()
	{
		for (let i in this._screenShieldInj)
			removeInjection(ScreenShield.ScreenShield.prototype, this._screenShieldInj, i);
		for (let i in this._modalDialogInj)
			removeInjection(ModalDialog.ModalDialog.prototype, this._modalDialogInj, i);
		for (let i in this._workViewInj)
			removeInjection(WorkspacesView.WorkspacesView.prototype, this._workViewInj, i);
		for (let i in this._switcherListInj)
			removeInjection(SwitcherPopup.SwitcherList.prototype, this._switcherListInj, i);
		for (let i in this._popupMenuInj)
			removeInjection(PopupMenu.PopupMenu.prototype, this._popupMenuInj, i);
		this._uninjectExtensions();		
		this.resetInjections();

		for (let i in uiPopupMenus)
		{
			let p = uiPopupMenus[i];
			p.destroy();
		}
		uiPopupMenus = {};
		for (let i in uiPanels)
		{
			let p = uiPanels[i];
			p.destroy();
		}
		uiPanels = {};

		for (let i in uiActors)
		{
			let p = uiActors[i];
			p.destroy();
		}
		uiActors = {};

		if (Main.panel.coherenceId != undefined)
			Main.panel.coherenceId = undefined;

		this.enabled = false;
	},

	actualizeWindows: function()
	{
		if (!this.enabled)
			return;
		for (let i in uiPanels)
		{
			let p = uiPanels[i];
			p.updateGeom();
		}
	},
});

const PrlWindowTracker = new Lang.Class
({
	Name: 'PrlWindowTracker',

	_init: function()
	{
		this._metaTrack = new PrlMetaTracker();
		this._wnckTrack = new PrlWnckTracker();
		this._uiTrack = new PrlUITracker();

		this._enabled = false;

		log(PRL_PFX + 'Tracker created.')
	},

	destroy: function()
	{
		this.disable();

		this._metaTrack.destroy();
		this._wnckTrack.destroy();
		this._uiTrack.destroy();

		log(PRL_PFX + 'Tracker destroyed.')
	},

	enable: function()
	{
		if (this._enabled)
			return;
		this._enabled = true;

		this._metaTrack.enable();
		this._wnckTrack.enable();
		this._uiTrack.enable();

		this.actualizeWindows();

		log(PRL_PFX + 'Tracker enabled.')
	},

	disable: function()
	{
		if (!this._enabled)
			return;
		this._enabled = false;

		this._metaTrack.disable();
		this._wnckTrack.disable();
		this._uiTrack.disable();

		log(PRL_PFX + 'Tracker disabled.')
	},

	actualizeWindows: function()
	{
		this._metaTrack.actualizeWindows();
		this._wnckTrack.actualizeWindows();
		this._uiTrack.actualizeWindows();
	},
});

function init()
{
	tracker = new PrlWindowTracker();
	coherenceSetup = new CoherenceSetupInterface();
	coherence = new CoherenceInterface();
}

function enable()
{
	tracker.enable();
}

function disable()
{
	// Commented, because Lock Screen may disable us.
	//	tracker.disable();
}
