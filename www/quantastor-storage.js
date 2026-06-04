/*
 * QuantaStor storage plugin UI for Proxmox VE.
 *
 * Loaded via /pve2/js/quantastor-storage.js, injected into
 * /usr/share/pve-manager/index.html.tpl by the package postinst.
 *
 * Registers 'quantastor' in PVE.Utils.storageSchema so the type appears in
 * the Add Storage menu and has a dedicated edit dialog.
 */

PVE.Utils.storageSchema.quantastor = {
    name: 'QuantaStor',
    ipanel: 'QuantaStorInputPanel',
    faIcon: 'building',
    backups: false,
};

Ext.define('PVE.storage.QuantaStorInputPanel', {
    extend: 'PVE.panel.StorageBase',

    onGetValues: function(values) {
	let me = this;

	if (!values.password || values.password === '********') {
	    delete values.password;
	}

	if (values.portal === '') {
	    delete values.portal;
	    if (!me.isCreate) {
		values.delete = values.delete ? values.delete + ',portal' : 'portal';
	    }
	}

	return me.callParent([values]);
    },

    // Auto-fill the storage ID field with the first available qs-storage-N.
    autoFillStorageId: function() {
	let me = this;
	if (!me.isCreate) return;

	Proxmox.Utils.API2Request({
	    url: '/storage',
	    method: 'GET',
	    failure: function() { /* silently skip if storage list unavailable */ },
	    success: function(response) {
		let existing = {};
		(response.result.data || []).forEach(function(s) {
		    existing[s.storage] = true;
		});

		let n = 1;
		while (existing['qs-storage-' + n]) n++;
		let suggestedId = 'qs-storage-' + n;

		let idField = me.down('field[name=storage]');
		if (idField && !idField.getValue()) {
		    idField.setValue(suggestedId);
		}
	    },
	});
    },

    // Scan the QuantaStor appliance and populate the pool dropdown.
    scanPools: function() {
	let me = this;

	let apiHost  = me.down('field[name=api_host]').getValue();
	let username = me.down('field[name=username]').getValue() || 'admin';
	let password = me.down('field[name=password]').getValue();
	let sslVerify = me.down('field[name=ssl_verify]').getValue() ? 1 : 0;
	let poolCombo = me.down('combobox[name=pool_id]');

	if (!apiHost) {
	    Ext.Msg.alert(gettext('Error'), gettext('Enter API Host before scanning.'));
	    return;
	}
	if (!password) {
	    Ext.Msg.alert(gettext('Error'), gettext('Enter Password before scanning.'));
	    return;
	}

	// Guard against overlapping scans (e.g. rapid double-click): a second
	// in-flight request can race the first's loadData/setValue and leave the
	// combo referencing a dropped record.
	if (me.scanInFlight) {
	    return;
	}
	me.scanInFlight = true;
	poolCombo.setLoading(true);

	let node = Proxmox.NodeName || 'localhost';

	Proxmox.Utils.API2Request({
	    url: '/nodes/' + node + '/scan/quantastor',
	    method: 'GET',
	    params: {
		api_host:   apiHost,
		username:   username,
		password:   password,
		ssl_verify: sslVerify,
	    },
	    failure: function(response) {
		me.scanInFlight = false;
		poolCombo.setLoading(false);
		let msg = response.htmlStatus || gettext('Scan failed. Check API Host and credentials.');
		Ext.Msg.alert(gettext('Scan Failed'), msg);
	    },
	    success: function(response) {
		me.scanInFlight = false;
		poolCombo.setLoading(false);
		let pools = response.result.data || [];
		if (!pools.length) {
		    Ext.Msg.alert(gettext('No Pools Found'),
			gettext('Connected to QuantaStor but no active pools were found.'));
		    return;
		}
		let store = poolCombo.getStore();
		store.loadData(pools.map(function(p) {
		    return { name: p.name, id: p.id, status: p.status };
		}));
		// Pre-select if only one pool.
		if (pools.length === 1) {
		    poolCombo.setValue(pools[0].name);
		}
	    },
	});
    },

    initComponent: function() {
	let me = this;

	me.column1 = [
	    {
		xtype: me.isCreate ? 'textfield' : 'displayfield',
		name: 'api_host',
		value: '',
		fieldLabel: gettext('API Host'),
		allowBlank: false,
	    },
	    {
		xtype: me.isCreate ? 'textfield' : 'displayfield',
		name: 'username',
		value: 'admin',
		fieldLabel: gettext('Username'),
		allowBlank: false,
	    },
	    {
		xtype: me.isCreate ? 'textfield' : 'displayfield',
		inputType: 'password',
		name: 'password',
		value: me.isCreate ? '' : '********',
		fieldLabel: gettext('Password'),
		allowBlank: !me.isCreate,
	    },
	    {
		// Pool field: combobox with Scan trigger on create; displayfield on edit.
		xtype: me.isCreate ? 'combobox' : 'displayfield',
		name: 'pool_id',
		fieldLabel: gettext('Pool'),
		allowBlank: false,
		editable: true,
		forceSelection: false,
		valueField: 'name',
		displayField: 'name',
		queryMode: 'local',
		store: {
		    fields: ['name', 'id', 'status'],
		    data: [],
		},
		emptyText: me.isCreate ? gettext('Enter pool name or click Scan') : '',
		triggers: me.isCreate ? {
		    scan: {
			cls: 'x-form-search-trigger',
			tooltip: gettext('Scan QuantaStor for pools'),
			handler: function() {
			    me.scanPools();
			},
		    },
		} : undefined,
	    },
	];

	me.column2 = [
	    {
		xtype: 'pveContentTypeSelector',
		name: 'content',
		value: 'images',
		cts: ['images'],
		fieldLabel: gettext('Content'),
		allowBlank: false,
	    },
	];

	me.advancedColumn1 = [
	    {
		xtype: 'textfield',
		name: 'portal',
		value: '',
		fieldLabel: gettext('iSCSI Portal'),
		emptyText: gettext('defaults to API Host'),
		allowBlank: true,
	    },
	];

	me.advancedColumn2 = [
	    {
		xtype: 'proxmoxcheckbox',
		name: 'ssl_verify',
		uncheckedValue: 0,
		defaultValue: 0,
		fieldLabel: gettext('SSL Verify'),
	    },
	];

	me.callParent();

	if (me.isCreate) {
	    me.autoFillStorageId();
	}
    },
});
