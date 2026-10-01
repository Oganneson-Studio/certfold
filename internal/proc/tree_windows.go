//go:build windows

package proc

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// start starts cmd in a new job object, which the processes it starts join,
// and makes the cancellation of cmd terminate the whole job. Until release,
// closing the job's last handle kills what runs in it, which Windows does
// when this process exits. release lifts that, so that the processes left in
// the job when the program exits by itself keep running, as on Unix.
func start(ctx context.Context, cmd *exec.Cmd) (release func(), err error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	release = func() {
		_ = killOnClose(job, false)
		_ = windows.CloseHandle(job)
	}
	if err := killOnClose(job, true); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	// Suspended, the program cannot start a process before it is in the job.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	cmd.Cancel = func() error { return windows.TerminateJobObject(job, 1) }
	if err := cmd.Start(); err != nil {
		release()
		return nil, err
	}
	if err := assign(job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		release()
		return nil, err
	}
	if ctx.Err() != nil {
		// exec may have cancelled cmd before the program was in the job,
		// which then killed nothing.
		_ = windows.TerminateJobObject(job, 1)
		return release, nil
	}
	if err := resume(uint32(cmd.Process.Pid)); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Wait()
		release()
		return nil, err
	}
	return release, nil
}

// killOnClose sets whether closing the last handle of job kills the processes
// in it. It is the only limit Certfold sets on a job.
func killOnClose(job windows.Handle, kill bool) error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if kill {
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("set job object limits: %w", err)
	}
	return nil
}

// assign puts the process pid in job.
func assign(job windows.Handle, pid int) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open program process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("assign program to job object: %w", err)
	}
	return nil
}

// resume resumes the process pid, created suspended: a process created so has
// a single thread until it runs.
func resume(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("resume program: %w", err)
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return fmt.Errorf("resume program: %w", err)
		}
		_, err = windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		if err != nil {
			return fmt.Errorf("resume program: %w", err)
		}
		return nil
	}
	return fmt.Errorf("resume program: no thread found: %w", err)
}
