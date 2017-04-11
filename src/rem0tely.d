import std.stdio;

immutable string usage =
`Usage:
`~`rem0tely [options] user@host [options] -- command [args for command]
`~/+`
`~`This requires the local machine to have an entry similar to this in its
`~`/etc/exports file:
`~`
`~`/             localhost(insecure,rw,fsid=root,no_root_squash)
`~+/`
`~`The local user must have a default private key identity (~/.ssh/xxx_id) file
`~`that is authorized to log in as the user on the host machine.  This identity
`~`must also be allowed to open forward ssh tunnels on the host machine, and it
`~`might also be a good idea to set up X11 forwarding if a graphical application
`~`is being ran this way.
`~`
`~`The rem0tely-host program must be in the user's PATH on the host machine.
`~`
`~`Options:
`~`     --help
`~`             Displays this help message.  All other arguments are ignored
`~`             when this is used.
`~`
`~`     --no-sudo
`~`             Prevents rem0tely from invoking itself with the 'sudo' command
`~`             automatically when it runs into permissions problems.
`~`
`~`     --nfs-afterwards {on,off,earlier}
`~`     --nfs-afterwards={on,off,earlier}
`~`             This option determines whether the NFS service is left running
`~`             or stopped after rem0tely finishes executing the remote task.
`~`             The 'earlier' value will turn the NFS service off only if it
`~`             was already off when rem0tely began executing.
`~`             The default is --nfs-afterwards=earlier
`~`
`~`     --ssh-opts <string>
`~`     --ssh-opts=<string>
`~`             Pass the ssh options given in the string to the ssh invocation.
`;

/// Throwing this will cause the program to exit, but it will not print any
/// stack traces or other debugging information.  This is intended for when
/// code needs the program to exit gracefully and immediately, and has already
/// provided the user all of the information they need to know (if any).
class AbortException : Exception
{
	this() { super(""); }
}

/// Similar to AbortException, except throwing this will cause printUsage to
/// be called before exit.  Note that printUsage will only print usage if it
/// hasn't been printed already, so it is safe to throw this as a way to
/// guarantee that usage will be printed without the risk of printing twice.
class UsageException : Exception
{
	this() { super(""); }
}

/// Allows the --help argument to exit the program.
/// This will print usage when it exits.
class PrintUsage : Exception
{
	this() { super(""); }
}

/// This is used when rem0tely escalates itself using sudo:
/// it does so by executing itself with sudo, which means
/// that the first instance will need to exit as soon as
/// the sudo'd instance finishes.  It exits by throwing this.
class SudoEscalation : Exception
{
	private int _execStatus;
	@property int execStatus() const { return _execStatus; }
	this(int execStatus)
	{
		super("");
		this._execStatus = execStatus;
	}
}

enum NfsAfterwards
{
	on,
	off,
	earlier
}

class Config
{
	import  std.datetime : SysTime;

	string[]       args;
	string         userhost;
	string         command;
	string[]       commandArgs;
	string         sshOpts = "";

	// Internal state.
	bool           neverSudo = false;
	SysTime        startTime;
	bool           nfsWasOn = false;
	NfsAfterwards  nfsAfter = NfsAfterwards.earlier;

	this(string[] args) {
		import std.datetime : Clock;
		this.args = args;
		this.startTime = Clock.currTime();
	}
}

int _main(string[] args)
{
	Config cfg = parseArgs(args);
	ensureNfsStarted(cfg);
	scope(exit) finalizeNfsService(cfg);
	setupNfsEntry(cfg);
	scope(exit) clearNfsEntry(cfg);
	return runCommand(cfg);
}

int main(string[] args)
{
	int result = 1;
	try result = _main(args);
	catch(UsageException e) {
		result = 1;
		printUsage();
	}
	catch(AbortException e) result = 1;
	catch(PrintUsage e) {
		result = 0;
		printUsage();
	}
	catch(SudoEscalation e) result = e.execStatus;
	return result;
}

void printUsage()
{
	static bool usagePrinted = false;

	if ( usagePrinted )
		return;

	stdout.writeln(usage);
	usagePrinted = true;
}

Config parseArgs(string[] args)
{
	import std.algorithm.searching : canFind, findSplit, startsWith;

	foreach(arg; args[1..$])
		if ( arg == "--help" )
			throw new PrintUsage();

	if ( args.length < 4 ) {
		printUsage();
		stderr.writeln("rem0tely: Error: Need at least 3 arguments (including the --).");
		throw new UsageException();
	}

	auto cfg = new Config(args);
	for ( size_t i = 1; i < args.length; i++ )
	{
		string arg = args[i];
		string value = null;

		auto valSplit = arg.findSplit("=");
		arg = valSplit[0];
		value = valSplit[2];

		void consumeValue(string optName)
		{
			if ( value !is null && value.length > 0 )
				return; // The findSplit already parsed it out.

			i++;

			if ( i < args.length && !args[i].startsWith("--") )
				value = args[i];
			else
			{
				printUsage();
				stderr.writefln(
					"rem0tely: Error: Missing value for argument "~optName);
				throw new UsageException();
			}
		}

		if ( arg == "--nfs-afterwards" )
			consumeValue("--nfs-afterwards");
		else
		if ( arg == "--ssh-opts" )
			consumeValue("--ssh-opts");

		void errorUnrecognizedValue() {
			printUsage();
			stderr.writefln(
				"rem0tely: Error: "~
				"Unrecognized value for the %s option: %s", arg, value);
			throw new UsageException();
		}

		if ( arg.canFind('@') )
			cfg.userhost = arg;
		else
		if ( arg == "--no-sudo" )
			cfg.neverSudo = true;
		else
		if ( arg == "--nfs-afterwards=" )
		{
			switch(value)
			{
				case "on":      cfg.nfsAfter = NfsAfterwards.on;      break;
				case "off":     cfg.nfsAfter = NfsAfterwards.off;     break;
				case "earlier": cfg.nfsAfter = NfsAfterwards.earlier; break;
				default:        errorUnrecognizedValue();
			}
		}
		else
		if ( arg == "--ssh-opts" )
			cfg.sshOpts = value;
		else
		if ( arg == "--" )
		{
			if ( i+1 < args.length ) {
				cfg.command = args[i+1];
				cfg.commandArgs = args[i+2..$];
			}
			break;
		}
		else
		{
			printUsage();
			stderr.writefln("rem0tely: Error: Unrecongized argument %s", arg);
			throw new UsageException();
		}
	}

	if ( cfg.userhost is null || cfg.userhost == "" ) {
		printUsage();
		stderr.writeln("rem0tely: Error: Missing user@host information.");
		throw new UsageException();
	}

	if ( cfg.command is null || cfg.command == "" ) {
		printUsage();
		stderr.writeln("rem0tely: Error: Missing command to run.");
		throw new UsageException();
	}

	return cfg;
}

bool nfsIsStarted(const Config cfg)
{
	import std.process;
	// The error handling in this function is simplified by a couple things:
	// - We don't need to determine failure modes precisely.  If we can't
	//   prove that it's started, then it's sufficient to consider it stopped
	//   and then let the rest of the code attempt to (re)start it.
	// - The "status" command doesn't seem to require root priveleges, so
	//   we don't bother checking for permisions failures.
	auto ret = execute(["/etc/init.d/nfs","--quiet","status"]);
	return (ret.status == 0);
}

void ensureNfsStarted(Config cfg)
{
	import std.algorithm.searching : canFind;
	import std.array;
	import std.exception : assumeUnique;
	import std.process;
	import std.stdio;
	import std.string : strip;

	// We can avoid unnecessary steps and output less spam by doing a simple
	// check on the NFS service's status first.
	if ( nfsIsStarted(cfg) )
	{
		cfg.nfsWasOn = true;
		return;
	}
	else
		cfg.nfsWasOn = false;

	// If we don't have a started NFS service, then we will start it
	// atomically using '/etc/init.d/nfs --ifstopped start', but this will
	// take some doing as detailed below.

	// Long story short: we'll need bash's help with this, so our first step
	// is to find out where the bash binary lives.
	auto whichBash = execute(["which","bash"]);
	if ( whichBash.status != 0 )
	{
		stderr.writeln (whichBash.output);
		stderr.writeln ("rem0tely: Could not find bash.");
		stderr.writeln ("rem0tely: Search was attempted by running 'which bash',");
		stderr.writefln("rem0tely: but that returned code %d", whichBash.status);
		throw new AbortException();
	}

	auto bashPath = whichBash.output.strip;

	//string nfsStartCmd = "/etc/init.d/nfs --ifstopped start";

	//auto res = executeShell(nfsStartCmd);
	//auto res = execute(["/etc/init.d/nfs","--ifstopped","start"]);
	//auto pipes = pipeShell(nfsStartCmd,  Redirect.stdin | Redirect.stdout | Redirect.stderrToStdout);
	debug writeln("Running openrc-run.");

	// The bash snippet below is a bit of a monstrosity; sorry.
	// However, there are reasons.
	// The '/etc/init.d/nfs --ifstopped start' is ultimately what we are trying
	// to do, and this part of the bash code is pretty normal and it will do
	// what you expect.
	// There is a problem, though.  There's always a problem!
	// There's some strange behavior in D's process execution stack that
	// interacts with openrc scripts and causes a good 30-second delay after
	// the script exits and before the D program resumes execution (timed on
	// an Intel Core i5 M540, if it matters).  Before I had that narrowed down,
	// I wanted some way to let the openrc script's stdout reach the user in
	// real time so that we can see what's taking time if there's a slowdown,
	// yet the output going to stdout needs to be available to the D code as
	// well for the purposes of identifying permissions failures.
	// The solution was to collapse the stderr/stdout of the openrc script
	// into stdout (2>&1), feed that to tee, then replace tee's file output
	// with a process substitution that cat's the duplicated stdout to stderr.
	// (That trick came from here: http://stackoverflow.com/questions/3141738/duplicating-stdout-to-stderr )
	// This means the entirety of the openrc script's output is available on
	// both stdout and stderr, and we can use pipeShell to redirect one to the
	// D program while leaving the other to head to the terminal.
	// Cool.  Problem solved.  NOOOOOPE.
	// The return code then became the result of the cat or the tee command
	// (not sure which; it doesn't matter because they are both just about
	// guaranteed to return 0, and the openrc script's return gets discarded
	// either way).  Well, that one is fixed by the pipefail bit:
	// http://stackoverflow.com/questions/1221833/pipe-output-and-capture-exit-status-in-bash
	// So now we have uncolored output and the thing runs sloooow, but at least
	// we can monitor it and detect whether it is successful or not.  Progress!
	// As it turns out, the remaining two problems can be solved by wrapping
	// the openrc script up into the "script" command:
	// http://stackoverflow.com/questions/1401002/trick-an-application-into-thinking-its-stdin-is-interactive-not-a-pipe
	// This was originally a stab at color pass-through, but it had the
	// very beneficial side-effect of causing execution to return to the D
	// program the instant that the openrc script (and everything else in the
	// bash snippet) finishes its job.  Presumably, the "script" command is more
	// like the majority of programs that DO NOT exit slowly under the D process
	// module (maybe C would do it too?), and it itself also doesn't cause the
	// openrc script to exit slowly, so wrapping the one in the other sidesteps
	// the whole problem entirely.  Wonderful!
	// And that's how it got like this.
	auto pipes = pipeShell(
		`set -o pipefail; `~
		`script --quiet --return -c "`~
		`/etc/init.d/nfs --ifstopped start" /dev/null `~
		`2>&1 | tee >(cat >&2)`,
		Redirect.stderr, // Only redirect stderr to the pipes object.  Everything else is user interaction.
		null, std.process.Config.none, null, // env, config, and workDir: just use defaults.
		bashPath); // We're filling out the args to get to this: now we can replace sh with bash.

	auto byteSink = std.array.appender!(ubyte[])();
	auto ret = tryWait(pipes.pid);
	while(!ret.terminated)
	{
		import core.thread;
		Thread.sleep( dur!("msecs")( 10 ) );
		foreach(ubyte[] buffer; pipes.stderr.byChunk(new ubyte[1024]))
			byteSink.put(buffer);
		ret = tryWait(pipes.pid);
	}

	//auto returnCode = wait(pipes.pid);
	//string output = pipes.stdout.byLine.join("\n").assumeUnique;
	auto returnCode = ret.status;
	auto output = (cast(char[])byteSink.data).assumeUnique;

	/+
	auto ret = executeShell("/etc/init.d/nfs start",
		null, std.process.Config.none, size_t.max, null, bashPath);
	auto returnCode = ret.status;
	auto output = ret.output;
+/

	debug writefln("Done: openrc-run. (%d)", returnCode);

	// We check for return code 1 and an empty output, because this is how
	// openrc-run behaves when the service is already started and we run
	// the above command.  We only get the 0 return code if the command
	// had to start the service (and it succeeded).
	if ( returnCode == 0 )
		return; // Success.
	else
	if ( returnCode == 1 && output.strip == "" )
	{
		writeln("rem0tely: Started NFS server on local machine.");
		return; // Success.
	}

	// At this point in code, there is some error.
	// First things first: let the user see the error reported by the initscript.
	//stderr.writeln(output);
	// Update: Now that we duplicate stdout/stderr and show the user the output
	// in real time, there is no more need to print it to them explicitly.

	// We might be able to run sudo on ourselves and get the necessary
	// permissions.  If that works, sudoEscalate will jump to the main()
	// function and exit (without displaying any other error messages from
	// this function).  If it doesn't work, we'll write our blurp about
	// how we couldn't start NFS and we need that.
	if ( output.canFind("superuser access required") )
		sudoEscalate(cfg);

	// Failure for reasons besides needing root access.
	stderr.writeln ("rem0tely: Error: Failed to start NFS on local machine.");
	stderr.writefln("rem0tely: Received return code %d from /etc/init.d/nfs.", returnCode);
	stderr.writeln ("rem0tely: This makes it impossible to continue, so this operation will be aborted.");
	throw new AbortException();

	/+
	void abort() {
		stderr.writeln("rem0tely: Error: Failed to start NFS on local machine.");
		stderr.writeln("rem0tely: This makes it impossible to continue, so this operation will be aborted.");
		throw new AbortException();
	}
	...

	if ( !alwaysSudo )
	{
		auto res = executeShell(nfsStartCmd);
		if ( res.status == 0 )
			return; // Success.

		if ( res.output.countUntil("superuser access required") < 0 ) {
			// Failure for reasons besides needing root access.
			stderr.writeln(res.output);
			abort();
		}

		// Failure because we need root.
		cfg.alwaysSudo = true;
	}

	// Now we try to use sudo to escalate to root.
	// This can possibly use a password prompt, so we use pipeShell to allow
	// stdin to be redirected.  We won't be able to buffer and search the
	// output like with executeShell, but that is OK here; we wouldn't be able
	// to do anything with it at this point anyways.
	auto pipes = pipeShell("sudo "~nfsStartCmd);
	if ( wait(pipes.pid) == 0 )
		return; // Success.

	abort(); // Failure in general.
	+/
}

private string getBindPath(Config cfg)
{
	import std.algorithm.searching : findSplitBefore;
	import std.datetime;
	import std.format;
	import std.process : thisProcessID;

	// We insert the PID to ensure that our link will not collide with other
	// instances of rem0tely that might be started within the same second.
	// We insert the startTime to ensure that our link will not collide with
	// with a future instance of rem0tely if the current instance fails to
	// delete its link or fails to remote its NFS export entry from the
	// system's NFS exports table (the future instance would also need to have
	// the incredible misfortune of receiving the same PID).
	auto pid = thisProcessID();
	auto timestr = cfg.startTime.toISOString().findSplitBefore(".")[0];

	// TODO: Is formatting PIDs with %d portable?
	// I know VMS doesn't format PIDs with %d (it conventionally uses hex to
	// display PIDs), but is there any operating system that I care about that
	// does it differently?
	return format("/tmp/rem0tely-%s-%d",timestr,pid);;
}

void setupNfsEntry(Config cfg)
{
	import std.file : mkdir;

	string bindPath = getBindPath(cfg);

	// This will throw if something goes wrong, so further error handling
	// is not required for this operation.
	mkdir(bindPath);
	scope(failure) removeMountPoint(cfg, bindPath);

	bindMount(cfg, bindPath);
	scope(failure) bindUnmount(cfg, bindPath);

	addExport(cfg, bindPath);

	/+
	import std.algorithm.searching : countUntil;

	void abort() {
		stderr.writeln("rem0tely: Error: Failed add NFS share to exports table.");
		throw new AbortException();
	}

	auto local_uid = geteuid();
	auto local_gid = getegid();

	string linkPath = getLinkPath(cfg);

	// This will throw if there's a problem.
	// (It will also throw if the link exists already, and because it throws
	// with the same FileException as other problems, this is kind of annoying
	// because of how it becomes difficult to identify whether the outcome is
	// acceptable or not.  However, this program should never have created this
	// link before, so we should never get a FileException from an
	// already-existing link, at least in our case.)
	symlink("/", linkPath);

	if ( !alwaysSudo )
	{
		string exportfsCmd = format(
			"exportfs -o insecure,rw,fsid=root,nohide,crossmnt,no_subtree_check,all_squash,"~
			"anonuid=%d,anongid=%d localhost:%s",
			local_uid, local_gid, linkPath);

		auto res = executeShell(exportfsCmd);
		if ( res.status == 0 )
			return; // Success.

		if ( res.output.countUntil("command not found") < 0
		&&   res.output.countUntil("Permission denied") < 0 ) {
			// Failure for reasons besides needing root access.
			stderr.writeln(res.output);
			abort();
		}

		// Failure because we (maybe) need root.
		alwaysSudo = true;
	}

	// Now we try to use sudo to escalate to root.
	// This can possibly use a password prompt, so we use pipeShell to allow
	// stdin to be redirected.  We won't be able to buffer and search the
	// output like with executeShell, but that is OK here; we wouldn't be able
	// to do anything with it at this point anyways.
	auto pipes = pipeShell("sudo "~exportfsCmd);
	if ( wait(pipes.pid) != 0 )
		abort();

	// Success!
	+/
}

void bindMount(Config cfg, string bindPath)
{
	import std.algorithm.searching : canFind;
	import std.process;

	auto res = execute(["mount","--bind","/",bindPath]);
	if ( res.status == 0 )
		return; // Success.

	// Display mount's error(s) to the user.
	stderr.writeln (res.output);

	// Identify permission failure by looking part of this error:
	//   mount: only root can use "--bind" option
	if ( res.output.canFind("only root") )
		sudoEscalate(cfg);

	// We end up here if sudo failed.
	// So we'll just report our version of what happened, and then exit.
	stderr.writefln("rem0tely: Error: Failed to mount bind %s", bindPath);
	throw new AbortException();
}

void addExport(Config cfg, string bindPath)
{
	import core.sys.posix.unistd : getegid, geteuid;
	import std.algorithm.searching : canFind;
	import std.format;
	import std.process;

	auto local_uid = geteuid();
	auto local_gid = getegid();

	string exportfsCmd = format(
		"exportfs -o insecure,rw,fsid=root,nohide,crossmnt,no_subtree_check,all_squash,"~
		"anonuid=%d,anongid=%d localhost:%s",
		local_uid, local_gid, bindPath);

	debug writeln("Running exportfs");
	auto res = executeShell(exportfsCmd);
	debug writeln("Done: exportfs");
	if ( res.status == 0 )
		return; // Success.

	// Display exportfs's error(s) to the user.
	stderr.writeln(res.output);

	// Attempt to sudo.
	if ( res.output.canFind("command not found")
	||   res.output.canFind("Permission denied") )
		sudoEscalate(cfg);

	// We end up here if sudo failed.
	// So we'll just report our version of what happened, and then exit.
	stderr.writeln("rem0tely: Error: Failed to add NFS share to exports table.");
	throw new AbortException();
}

void clearNfsEntry(Config cfg)
{
	string bindPath = getBindPath(cfg);

	removeExport(cfg, bindPath);
	bindUnmount(cfg, bindPath);
	removeMountPoint(cfg, bindPath);

	/+
	string linkPath = getLinkPath(cfg);

	auto pipes = pipeShell(format("exportfs -u localhost:%s",linkPath));
	if ( wait(pipes.pid) != 0 ) {
		stderr.writeln("rem0tely: Warning: Failed remove NFS share (localhost:%s)", linkPath);
		stderr.writeln("rem0tely:          from exports table.");
		stderr.writeln("rem0tely:          The entry is only sharing to localhost, so");
		stderr.writeln("rem0tely:          it should not cause significant security");
		stderr.writeln("rem0tely:          issues, but this could junk up the exports table");
		stderr.writeln("rem0tely:          If you desire to fix this, then you may want to");
		stderr.writeln("rem0tely:          consult the 'exportfs' manpage to learn how to");
		stderr.writeln("rem0tely:          use the 'exportfs' command to examine or remove");
		stderr.writeln("rem0tely:          NFS exports table entries.");
	}

	try
		remove(linkPath);
	catch ( FileException e ) {
		stderr.writeln (e.msg);
		stderr.writefln("rem0tely: Warning: Could not remove root-directory symlink %s", linkPath);
		stderr.writeln ("rem0tely:          This symlink is used to identify unique NFS settings.");
		stderr.writeln ("rem0tely:          If it still exists, it shouldn't cause any");
		stderr.writeln ("rem0tely:          problems.  It just adds clutter to /tmp");
	}
	+/
}

void removeMountPoint(Config cfg, string bindPath)
{
	import std.file;
	try
		std.file.remove(bindPath);
	catch ( FileException e ) {
		stderr.writeln (e.msg);
		stderr.writefln("rem0tely: Warning: Could not remove bind-mountable root-directory %s", bindPath);
		stderr.writeln ("rem0tely:          This mount point is used to identify unique NFS settings.");
		stderr.writeln ("rem0tely:          If it still exists, it shouldn't cause any");
		stderr.writeln ("rem0tely:          problems.  It just adds clutter to /tmp");
	}
}

void bindUnmount(Config cfg, string bindPath)
{
	import std.process;

	// Note that when we clean up resources, we should not call sudoEscalate
	// to attain higher priveleges.
	// In an ideal world, we would run sudo on the cleanup commands individually,
	// but as of this writing, it is not worth it: if sudo were required, we
	// would have hit that block when allocating resources, and at that point
	// we would have sudo'd our entire process, thus the cleanup routines will
	// run in a sudo'd environment anyways.

	auto pid = spawnProcess(["umount",bindPath]);
	if ( wait(pid) == 0 )
		return; // Success.

	/+
	// Don't do this.
	// The code is left here incase someone needs to know what string to
	// search for to identify umount permissions failures.
	import std.algorithm.searching : canFind;
	if ( output.canFind("Operation not permitted") >= 0 )
		sudoEscalate(cfg);
	+/

	// Issue a warning to ensure that the user will know there is something
	// not quite right with this.
	stderr.writefln("rem0tely: Warning: Failed to unmount bind %s", bindPath);
}

void removeExport(Config cfg, string bindPath)
{
	import std.process;

	auto pid = spawnProcess(["exportfs","-u","localhost:"~bindPath]);
	if ( wait(pid) == 0 )
		return;

	stderr.writeln("rem0tely: Warning: Failed remove NFS share (localhost:%s)", bindPath);
	stderr.writeln("rem0tely:          from exports table.");
	stderr.writeln("rem0tely:          The entry is only sharing to localhost, so");
	stderr.writeln("rem0tely:          it should not cause significant security");
	stderr.writeln("rem0tely:          issues, but this could junk up the exports table");
	stderr.writeln("rem0tely:          If you desire to fix this, then you may want to");
	stderr.writeln("rem0tely:          consult the 'exportfs' manpage to learn how to");
	stderr.writeln("rem0tely:          use the 'exportfs' command to examine or remove");
	stderr.writeln("rem0tely:          NFS exports table entries.");
}

int runCommand(Config cfg)
{
	import std.algorithm.iteration : joiner;
	import std.format;
	import std.process;

	debug writefln("Running command %s", cfg.command);
	auto pid = std.process.spawnShell(format(
		"ssh %s -R 2049:localhost:3049 %s rem0tely-host %s %s",
		cfg.sshOpts, cfg.userhost, cfg.command, cfg.commandArgs.joiner(" ")));
	debug writeln("Done: command");
	return wait(pid);
}

void finalizeNfsService(Config cfg)
{
	import std.process;

	final switch( cfg.nfsAfter )
	{
		case NfsAfterwards.on:
			// It's already on.
			return;

		case NfsAfterwards.off:
		case NfsAfterwards.earlier:
			if ( cfg.nfsAfter == NfsAfterwards.off
			||  (cfg.nfsAfter == NfsAfterwards.earlier && !cfg.nfsWasOn) )
			{
				auto pid = spawnShell(`script --quiet --return -c `~
					`"/etc/init.d/nfs stop" /dev/null`);
				if ( wait(pid) == 0 )
					return;
			}
			break;
	}
}

private void sudoEscalate(Config cfg)
{
	import std.process;

	if ( cfg.neverSudo )
		return;

	stderr.writeln("rem0tely: Received permissions error.  Attempting to sudo.");

	// We add --no-sudo to prevent any possibility of infinite recursion.
	auto pid = spawnProcess(["sudo"]~cfg.args[0]~["--no-sudo"]~cfg.args[1..$]);
	throw new SudoEscalation(wait(pid));
}

// TODO: Mount options: vers=4,