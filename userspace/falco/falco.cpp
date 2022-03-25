/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string>

#include <iostream>

#include "application.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used

static void display_fatal_err(const string &msg)
{
	falco_logger::log(LOG_ERR, msg);

	/**
	 * If stderr logging is not enabled, also log to stderr. When
	 * daemonized this will simply write to /dev/null.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(int argc, char **argv, bool &restart)
{
	falco::app::application app;
	restart = false;

	std::string errstr;
	bool successful = app.init(argc, argv, errstr);

	if(!successful)
	{
		fprintf(stderr, "Runtime error: %s. Exiting.\n", errstr.c_str());
		return EXIT_FAILURE;
	}

	try
	{
		bool success;
		std::string errstr;

		success = app.run(errstr, restart);

		if(!success)
		{
			fprintf(stderr, "Error: %s\n", errstr.c_str());
			return EXIT_FAILURE;
		}
<<<<<<< HEAD
=======

		engine = new falco_engine(true);

		configure_output_format(app, engine);

		// Create "factories" that can create filters/formatters for
		// syscalls and k8s audit events.
		std::shared_ptr<gen_event_filter_factory> syscall_filter_factory(new sinsp_filter_factory(inspector));
		std::shared_ptr<gen_event_filter_factory> k8s_audit_filter_factory(new json_event_filter_factory());

		std::shared_ptr<gen_event_formatter_factory> syscall_formatter_factory(new sinsp_evt_formatter_factory(inspector));
		std::shared_ptr<gen_event_formatter_factory> k8s_audit_formatter_factory(new json_event_formatter_factory(k8s_audit_filter_factory));

		engine->add_source(syscall_source, syscall_filter_factory, syscall_formatter_factory);
		engine->add_source(k8s_audit_source, k8s_audit_filter_factory, k8s_audit_formatter_factory);

		for(const auto &src : app.options().disable_sources)
		{
			enabled_sources.erase(src);
		}

		// XXX/mstemm technically this isn't right, you could disable syscall *and* k8s_audit and configure a plugin.
		if(enabled_sources.empty())
		{
			throw std::invalid_argument("The event source \"syscall\" and \"k8s_audit\" can not be disabled together");
		}

		if(app.options().validate_rules_filenames.size() > 0)
		{
			falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
			for(auto file : app.options().validate_rules_filenames)
			{
				falco_logger::log(LOG_INFO, "   " + file + "\n");
			}
			for(auto file : app.options().validate_rules_filenames)
			{
				// Only include the prefix if there is more than one file
				std::string prefix = (app.options().validate_rules_filenames.size() > 1 ? file + ": " : "");
				try {
					engine->load_rules_file(file, app.options().verbose, app.options().all_events);
				}
				catch(falco_exception &e)
				{
					printf("%s%s", prefix.c_str(), e.what());
					throw;
				}
				printf("%sOk\n", prefix.c_str());
			}
			falco_logger::log(LOG_INFO, "Ok\n");
			goto exit;
		}

		falco_configuration config;

		if (app.options().conf_filename.size())
		{
			config.init(app.options().conf_filename, app.options().cmdline_config_options);
			falco_logger::set_time_format_iso_8601(config.m_time_format_iso_8601);

			// log after config init because config determines where logs go
			falco_logger::log(LOG_INFO, "Falco version " + std::string(FALCO_VERSION) + " (driver version " + std::string(DRIVER_VERSION) + ")\n");
			falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + app.options().conf_filename + "\n");
		}
		else
		{
#ifndef BUILD_TYPE_RELEASE
			errstr = std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#else
			errstr = std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#endif
			throw std::runtime_error(errstr);
		}

		// The event source is syscall by default. If an input
		// plugin was found, the source is the source of that
		// plugin.
		std::string event_source = syscall_source;

		// All filterchecks created by plugins go in this
		// list. If we ever support multiple event sources at
		// the same time, this (and the below factories) will
		// have to be a map from event source to filtercheck
		// list.
		filter_check_list plugin_filter_checks;

		// Factories that can create filters/formatters for
		// the (single) source supported by the (single) input plugin.
		std::shared_ptr<gen_event_filter_factory> plugin_filter_factory(new sinsp_filter_factory(inspector, plugin_filter_checks));
		std::shared_ptr<gen_event_formatter_factory> plugin_formatter_factory(new sinsp_evt_formatter_factory(inspector, plugin_filter_checks));

		std::shared_ptr<sinsp_plugin> input_plugin;
		std::list<std::shared_ptr<sinsp_plugin>> extractor_plugins;
		for(auto &p : config.m_plugins)
		{
			std::shared_ptr<sinsp_plugin> plugin;
#ifdef MUSL_OPTIMIZED
			throw std::invalid_argument(string("Can not load/use plugins with musl optimized build"));
#else
			falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");

			plugin = sinsp_plugin::register_plugin(inspector,
							       p.m_library_path,
							       (p.m_init_config.empty() ? NULL : (char *)p.m_init_config.c_str()),
							       plugin_filter_checks);
#endif

			if(plugin->type() == TYPE_SOURCE_PLUGIN)
			{
				sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());

				if(input_plugin)
				{
					throw std::invalid_argument(string("Can not load multiple source plugins. ") + input_plugin->name() + " already loaded");
				}

				input_plugin = plugin;
				event_source = splugin->event_source();

				inspector->set_input_plugin(p.m_name);
				if(!p.m_open_params.empty())
				{
					inspector->set_input_plugin_open_params(p.m_open_params.c_str());
				}

				engine->add_source(event_source, plugin_filter_factory, plugin_formatter_factory);

			} else {
				extractor_plugins.push_back(plugin);
			}
		}

		// Ensure that extractor plugins are compatible with the event source.
		// Also, ensure that extractor plugins don't have overlapping compatible event sources.
		std::set<std::string> compat_sources_seen;
		for(auto plugin : extractor_plugins)
		{
			// If the extractor plugin names compatible sources,
			// ensure that the input plugin's source is in the list
			// of compatible sources.
			sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(plugin.get());
			const std::set<std::string> &compat_sources = eplugin->extract_event_sources();
			if(input_plugin &&
			   !compat_sources.empty())
			{
				if (compat_sources.find(event_source) == compat_sources.end())
				{
					throw std::invalid_argument(string("Extractor plugin not compatible with event source ") + event_source);
				}

				for(const auto &compat_source : compat_sources)
				{
					if(compat_sources_seen.find(compat_source) != compat_sources_seen.end())
					{
						throw std::invalid_argument(string("Extractor plugins have overlapping compatible event source ") + compat_source);
					}
					compat_sources_seen.insert(compat_source);
				}
			}
		}

		if(config.m_json_output)
		{
			syscall_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
			k8s_audit_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
			plugin_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
		}

		std::list<sinsp_plugin::info> infos = sinsp_plugin::plugin_infos(inspector);

		if(app.options().list_plugins)
		{
			std::ostringstream os;

			for(auto &info : infos)
			{
				os << "Name: " << info.name << std::endl;
				os << "Description: " << info.description << std::endl;
				os << "Contact: " << info.contact << std::endl;
				os << "Version: " << info.plugin_version.as_string() << std::endl;

				if(info.type == TYPE_SOURCE_PLUGIN)
				{
					os << "Type: source plugin" << std::endl;
					os << "ID: " << info.id << std::endl;
				}
				else
				{
					os << "Type: extractor plugin" << std::endl;
				}
				os << std::endl;
			}

			printf("%lu Plugins Loaded:\n\n%s\n", infos.size(), os.str().c_str());
			return EXIT_SUCCESS;
		}

		if(app.options().list_fields)
		{
			list_source_fields(engine, app.options().verbose, app.options().names_only, app.options().list_source_fields);
			return EXIT_SUCCESS;
		}

		if (app.options().rules_filenames.size())
		{
			config.m_rules_filenames = app.options().rules_filenames;
		}

		engine->set_min_priority(config.m_min_priority);

		config.m_buffered_outputs = !app.options().unbuffered_outputs;

		if(config.m_rules_filenames.size() == 0)
		{
			throw std::invalid_argument("You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml");
		}

		falco_logger::log(LOG_DEBUG, "Configured rules filenames:\n");
		for (auto filename : config.m_rules_filenames)
		{
			falco_logger::log(LOG_DEBUG, string("   ") + filename + "\n");
		}

		for (auto filename : config.m_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "Loading rules from file " + filename + ":\n");
			uint64_t required_engine_version;

			try {
				engine->load_rules_file(filename, app.options().verbose, app.options().all_events, required_engine_version);
			}
			catch(falco_exception &e)
			{
				std::string prefix = "Could not load rules file " + filename + ": ";

				throw falco_exception(prefix + e.what());
			}
			required_engine_versions[filename] = required_engine_version;
		}

		// Ensure that all plugins are compatible with the loaded set of rules
		for(auto &info : infos)
		{
			std::string required_version;

			if(!engine->is_plugin_compatible(info.name, info.plugin_version.as_string(), required_version))
			{
				throw std::invalid_argument(std::string("Plugin ") + info.name + " version " + info.plugin_version.as_string() + " not compatible with required plugin version " + required_version);
			}
		}

		for (auto substring : app.options().disabled_rule_substrings)
		{
			falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
			engine->enable_rule(substring, false);
		}

		if(app.options().disabled_rule_tags.size() > 0)
		{
			for(auto &tag : app.options().disabled_rule_tags)
			{
				falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
			}
			engine->enable_rule_by_tag(app.options().disabled_rule_tags, false);
		}

		if(app.options().enabled_rule_tags.size() > 0)
		{

			// Since we only want to enable specific
			// rules, first disable all rules.
			engine->enable_rule(all_rules, false);
			for(auto &tag : app.options().enabled_rule_tags)
			{
				falco_logger::log(LOG_INFO, "Enabling rules with tag: " + tag + "\n");
			}
			engine->enable_rule_by_tag(app.options().enabled_rule_tags, true);
		}

		if(app.options().print_support)
		{
			nlohmann::json support;
			struct utsname sysinfo;
			std::string cmdline;

			if(uname(&sysinfo) != 0)
			{
				throw std::runtime_error(string("Could not uname() to find system info: %s\n") + strerror(errno));
			}

			for(char **arg = argv; *arg; arg++)
			{
				if(cmdline.size() > 0)
				{
					cmdline += " ";
				}
				cmdline += *arg;
			}

			support["version"] = FALCO_VERSION;
			support["system_info"]["sysname"] = sysinfo.sysname;
			support["system_info"]["nodename"] = sysinfo.nodename;
			support["system_info"]["release"] = sysinfo.release;
			support["system_info"]["version"] = sysinfo.version;
			support["system_info"]["machine"] = sysinfo.machine;
			support["cmdline"] = cmdline;
			support["engine_info"]["engine_version"] = FALCO_ENGINE_VERSION;
			support["config"] = read_file(app.options().conf_filename);
			support["rules_files"] = nlohmann::json::array();
			for(auto filename : config.m_rules_filenames)
			{
				nlohmann::json finfo;
				finfo["name"] = filename;
				nlohmann::json variant;
				variant["required_engine_version"] = required_engine_versions[filename];
				variant["content"] = read_file(filename);
				finfo["variants"].push_back(variant);
				support["rules_files"].push_back(finfo);
			}
			printf("%s\n", support.dump().c_str());
			goto exit;
		}

		// read hostname
		string hostname;
		if(char* env_hostname = getenv("FALCO_GRPC_HOSTNAME"))
		{
			hostname = env_hostname;
		}
		else
		{
			char c_hostname[256];
			int err = gethostname(c_hostname, 256);
			if(err != 0)
			{
				throw falco_exception("Failed to get hostname");
			}
			hostname = c_hostname;
		}

		if(!app.options().all_events)
		{
			// For syscalls, see if any event types used by the
			// loaded rules are ones with the EF_DROP_SIMPLE_CONS
			// label.
			check_for_ignored_events(*inspector, *engine);
			// Drop EF_DROP_SIMPLE_CONS kernel side
			inspector->set_simple_consumer();
			// Eventually, drop any EF_DROP_SIMPLE_CONS event
			// that reached userspace (there are some events that are not syscall-based
			// like signaldeliver, that have the EF_DROP_SIMPLE_CONS flag)
			inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
		}

		if (app.options().describe_all_rules)
		{
			engine->describe_rule(NULL);
			goto exit;
		}

		if (!app.options().describe_rule.empty())
		{
			engine->describe_rule(&(app.options().describe_rule));
			goto exit;
		}

		inspector->set_hostname_and_port_resolution_mode(false);

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGTERM signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGUSR1, reopen_outputs) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGUSR1 signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGHUP, restart_falco) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGHUP signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		// If daemonizing, do it here so any init errors will
		// be returned in the foreground process.
		if (app.options().daemon && !g_daemonized) {
			pid_t pid, sid;

			pid = fork();
			if (pid < 0) {
				// error
				falco_logger::log(LOG_ERR, "Could not fork. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			} else if (pid > 0) {
				// parent. Write child pid to pidfile and exit
				std::ofstream pidfile;
				pidfile.open(app.options().pidfilename);

				if (!pidfile.good())
				{
					falco_logger::log(LOG_ERR, "Could not write pid to pid file " + app.options().pidfilename + ". Exiting.\n");
					result = EXIT_FAILURE;
					goto exit;
				}
				pidfile << pid;
				pidfile.close();
				goto exit;
			}
			// if here, child.

			// Become own process group.
			sid = setsid();
			if (sid < 0) {
				falco_logger::log(LOG_ERR, "Could not set session id. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			}

			// Set umask so no files are world anything or group writable.
			umask(027);

			// Change working directory to '/'
			if ((chdir("/")) < 0) {
				falco_logger::log(LOG_ERR, "Could not change working directory to '/'. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			}

			// Close stdin, stdout, stderr and reopen to /dev/null
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);

			g_daemonized = true;
		}

		outputs = new falco_outputs();

		outputs->init(engine,
			      config.m_json_output,
			      config.m_json_include_output_property,
			      config.m_json_include_tags_property,
			      config.m_output_timeout,
			      config.m_notifications_rate, config.m_notifications_max_burst,
			      config.m_buffered_outputs,
			      config.m_time_format_iso_8601,
			      hostname);

		for(auto output : config.m_outputs)
		{
			outputs->add_output(output);
		}

		if(app.options().trace_filename.size())
		{
			// Try to open the trace file as a
			// capture file first.
			try {
				inspector->open(app.options().trace_filename);
				falco_logger::log(LOG_INFO, "Reading system call events from file: " + app.options().trace_filename + "\n");
			}
			catch(sinsp_exception &e)
			{
				falco_logger::log(LOG_DEBUG, "Could not read trace file \"" + app.options().trace_filename + "\": " + string(e.what()));
				trace_is_scap=false;
			}

			if(!trace_is_scap)
			{
#ifdef MINIMAL_BUILD
				// Note that the webserver is not available when MINIMAL_BUILD is defined.
				fprintf(stderr, "Cannot use k8s audit events trace file with a minimal Falco build");
				result = EXIT_FAILURE;
				goto exit;
#else
				try {
					string line;
					nlohmann::json j;

					// Note we only temporarily open the file here.
					// The read file read loop will be later.
					ifstream ifs(app.options().trace_filename);
					getline(ifs, line);
					j = nlohmann::json::parse(line);

					falco_logger::log(LOG_INFO, "Reading k8s audit events from file: " + app.options().trace_filename + "\n");
				}
				catch (nlohmann::json::parse_error& e)
				{
					fprintf(stderr, "Trace filename %s not recognized as system call events or k8s audit events\n", app.options().trace_filename.c_str());
					result = EXIT_FAILURE;
					goto exit;
				}
				catch (exception &e)
				{
					fprintf(stderr, "Could not open trace filename %s for reading: %s\n", app.options().trace_filename.c_str(), e.what());
					result = EXIT_FAILURE;
					goto exit;
				}
#endif
			}
		}
		else
		{
			open_t open_cb = [&app](sinsp* inspector)
			{
				if(app.options().userspace)
				{
					// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
					//
					// Falco uses a ptrace(2) based userspace implementation.
					// Regardless of the implementation, the underlying method remains the same.
					inspector->open_udig();
					return;
				}

				if(app.options().gvisor_socket != "")
				{
					falco_logger::log(LOG_INFO, "Enabled event collection from gVisor. Socket path: " + app.options().gvisor_socket);
					inspector->open_gvisor(app.options().gvisor_socket);
					return;
				}
				
				inspector->open();
			};
			open_t open_nodriver_cb = [](sinsp* inspector) {
				inspector->open_nodriver();
			};
			open_t open_f;

			// Default mode: both event sources enabled
			if (enabled_sources.find(syscall_source) != enabled_sources.end() &&
			    enabled_sources.find(k8s_audit_source) != enabled_sources.end())
			{
				open_f = open_cb;
			}
			if (enabled_sources.find(syscall_source) == enabled_sources.end())
			{
				open_f = open_nodriver_cb;
			}
			if (enabled_sources.find(k8s_audit_source) == enabled_sources.end())
			{
				open_f = open_cb;
			}

			try
			{
				open_f(inspector);
			}
			catch(sinsp_exception &e)
			{
				// If syscall input source is enabled and not through userspace instrumentation
				if (enabled_sources.find(syscall_source) != enabled_sources.end() && !app.options().userspace)
				{
					// Try to insert the Falco kernel module
					if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
					{
						falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
					}
					open_f(inspector);
				}
				else
				{
					rethrow_exception(current_exception());
				}
			}
		}

		// This must be done after the open
		if(!app.options().all_events)
		{
			inspector->start_dropping_mode(1);
		}

		if(outfile != "")
		{
			inspector->setup_cycle_writer(outfile, rollover_mb, duration_seconds, file_limit, event_limit, compress);
			inspector->autodump_next_file();
		}

		duration = ((double)clock()) / CLOCKS_PER_SEC;

#ifndef MINIMAL_BUILD
		//
		// Run k8s, if required
		//
		char *k8s_api_env = NULL;
		if(!app.options().k8s_api.empty() ||
		   (k8s_api_env = getenv("FALCO_K8S_API")))
		{
			// Create string pointers for some config vars
			// and pass to inspector. The inspector then
			// owns the pointers.
			std::string *k8s_api_ptr = new string((!app.options().k8s_api.empty() ? app.options().k8s_api : k8s_api_env));
			std::string *k8s_api_cert_ptr = new string(app.options().k8s_api_cert);
			std::string *k8s_node_name_ptr = new string(app.options().k8s_node_name);

			if(k8s_api_cert_ptr->empty())
			{
				if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
				{
					*k8s_api_cert_ptr = k8s_cert_env;
				}
			}
			inspector->init_k8s_client(k8s_api_ptr, k8s_api_cert_ptr, k8s_node_name_ptr, app.options().verbose);
		}

		//
		// Run mesos, if required
		//
		if(!app.options().mesos_api.empty())
		{
			// Differs from init_k8s_client in that it
			// passes a pointer but the inspector does
			// *not* own it and does not use it after
			// init_mesos_client() returns.
			inspector->init_mesos_client(&(app.options().mesos_api), app.options().verbose);
		}
		else if(char* mesos_api_env = getenv("FALCO_MESOS_API"))
		{
			std::string mesos_api_copy = mesos_api_env;
			inspector->init_mesos_client(&mesos_api_copy, app.options().verbose);
		}

		falco_logger::log(LOG_DEBUG, "Setting metadata download max size to " + to_string(config.m_metadata_download_max_mb) + " MB\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download chunk wait time to " + to_string(config.m_metadata_download_chunk_wait_us) + " μs\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download watch frequency to " + to_string(config.m_metadata_download_watch_freq_sec) + " seconds\n");
		inspector->set_metadata_download_params(config.m_metadata_download_max_mb * 1024 * 1024, config.m_metadata_download_chunk_wait_us, config.m_metadata_download_watch_freq_sec);

		if(app.options().trace_filename.empty() && config.m_webserver_enabled && enabled_sources.find(k8s_audit_source) != enabled_sources.end())
		{
			std::string ssl_option = (config.m_webserver_ssl_enabled ? " (SSL)" : "");
			falco_logger::log(LOG_INFO, "Starting internal webserver, listening on port " + to_string(config.m_webserver_listen_port) + ssl_option + "\n");
			webserver.init(&config, engine, outputs);
			webserver.start();
		}

		// gRPC server
		if(config.m_grpc_enabled)
		{
			falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + to_string(config.m_grpc_threadiness) + "\n");
			// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
			// different queuing mechanisms, round robin, fanout? What we want to achieve?
			grpc_server.init(
				config.m_grpc_bind_address,
				config.m_grpc_threadiness,
				config.m_grpc_private_key,
				config.m_grpc_cert_chain,
				config.m_grpc_root_certs,
				config.m_log_level
			);
			grpc_server_thread = std::thread([&grpc_server] {
				grpc_server.run();
			});
		}
#endif

		if(!app.options().trace_filename.empty() && !trace_is_scap)
		{
#ifndef MINIMAL_BUILD
			read_k8s_audit_trace_file(engine,
						  outputs,
						  app.options().trace_filename);
#endif
		}
		else
		{
			uint64_t num_evts;

			num_evts = do_inspect(engine,
					      outputs,
					      inspector,
					      event_source,
					      config,
					      sdropmgr,
					      uint64_t(app.options().duration_to_tot*ONE_SECOND_IN_NS),
					      app.options().stats_filename,
					      app.options().stats_interval,
					      app.options().all_events,
					      result);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			inspector->get_capture_stats(&cstats);

			if(app.options().verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					num_evts,
					num_evts / duration);
			}

		}

		// Honor -M also when using a trace file.
		// Since inspection stops as soon as all events have been consumed
		// just await the given duration is reached, if needed.
		if(!app.options().trace_filename.empty() && app.options().duration_to_tot>0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(app.options().duration_to_tot));
		}

		inspector->close();
		engine->print_stats();
		sdropmgr.print_stats();
#ifndef MINIMAL_BUILD
		webserver.stop();
		if(grpc_server_thread.joinable())
		{
			grpc_server.shutdown();
			grpc_server_thread.join();
		}
#endif
>>>>>>> gvisor: configurable -g option
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int rc;
	bool restart;

	// Generally falco exits when falco_init returns with the rc
	// returned by falco_init. However, when restart (set by
	// signal handlers, returned in application::run()) is true,
	// falco_init() is called again.
	while((rc = falco_init(argc, argv, restart)) == EXIT_SUCCESS && restart)
	{
	}

	return rc;
}
