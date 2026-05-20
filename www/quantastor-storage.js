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

	// Don't submit password if left blank or unchanged on edit.
	if (!values.password || values.password === '********') {
	    delete values.password;
	}

	// Don't submit portal if left blank (Perl side defaults it to api_host).
	if (values.portal === '') {
	    delete values.portal;
	    if (!me.isCreate) {
		values.delete = values.delete ? values.delete + ',portal' : 'portal';
	    }
	}

	return me.callParent([values]);
    },

    initComponent: function() {
	let me = this;

	// StorageBase.initComponent() prepends the storage ID field to column1
	// and prepends Nodes + Enable to column2 automatically.

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
		xtype: me.isCreate ? 'textfield' : 'displayfield',
		name: 'pool_id',
		value: '',
		fieldLabel: gettext('Pool'),
		allowBlank: false,
	    },
	];

	me.column2 = [
	    {
		xtype: 'pveContentTypeSelector',
		name: 'content',
		value: 'images',
		multiSelect: true,
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
    },
});
