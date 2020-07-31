""" Wrapper class around list of active C plugins """
class plugin_list(dict):
	def __init__(self,panda):
		self._panda = panda
		super().__init__()
	def __getitem__(self,plugin_name):
		if plugin_name not in self:
			self._panda.load_plugin(plugin_name)
		return super().__getitem__(plugin_name)
