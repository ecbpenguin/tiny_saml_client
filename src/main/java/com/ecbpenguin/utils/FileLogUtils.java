package com.ecbpenguin.utils;

import java.io.File;
import java.io.FileWriter;

public class FileLogUtils {

	private static final String LOG_FILE="saml-Client-Error.log";

	private static FileWriter fw;
	
	static {
		try {
			final File logFile = new File(LOG_FILE);
			fw = new FileWriter(logFile, true);
		} catch (final Throwable e) {
			System.out.println(e.getMessage());
		} 
	}

	public static void log(final Throwable t) {
		logRecursive(t, true);
	}

	private static void logRecursive(final Throwable t, final boolean recurse) {
		if (fw == null || t == null) {
			System.out.println("Could not log due to null condition: " + t);
			return;
		}

		try {
			fw.write(t.toString());
			fw.write(System.lineSeparator());
			final StackTraceElement[] stes = t.getStackTrace();
			for (final StackTraceElement ste : stes) {
				fw.write("    at " + ste.getClassName() + "." + ste.getMethodName() + "():" + ste.getLineNumber());
				fw.write(System.lineSeparator());
			}
			fw.flush();
			//only do one level of recursion per cause
			if (recurse) {
				final Throwable[] ts = t.getSuppressed();
				for (final Throwable t3 : ts) {
					logRecursive(t3, false);
				}
			}
			final Throwable cause = t.getCause();
			if (cause != null ) {
				fw.write("caused by ");
				logRecursive(cause, true);
			}
		} catch (final Throwable t2) {
			System.out.println("Could not log due to exception : " + t2);
		}
	}
}
