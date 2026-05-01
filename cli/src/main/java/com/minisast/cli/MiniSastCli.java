package com.minisast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Main entry point for the Mini SAST CLI.
 *
 * Picocli's @Command annotation configures:
 *   - name:                  the binary name users type
 *   - mixinStandardHelpOptions: adds -h/--help and -V/--version automatically
 *   - subcommands:           registers child commands
 *
 * We implement Runnable only to show help when no subcommand is given.
 * All real logic lives in the subcommands.
 */
@Command(
        name        = "minisast",
        version     = "Mini SAST 0.1.0",
        description = "%nMini SAST — Static Application Security Testing Tool%n",
        mixinStandardHelpOptions = true,
        subcommands = {
                ScanCommand.class,
                CommandLine.HelpCommand.class
        }
)
public class MiniSastCli implements Runnable {

    @Override
    public void run() {
        // No subcommand given — print help
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new MiniSastCli())
                .setCaseInsensitiveEnumValuesAllowed(true)
                .setUsageHelpAutoWidth(true)
                .execute(args);
        System.exit(exitCode);
    }
}