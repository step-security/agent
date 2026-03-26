package main

import (
	"context"
	"fmt"

	"github.com/step-security/armour/armour"
)

// NOTE: before usage, make sure to nil check
var GlobalArmour *armour.Armour = nil

func InitArmour(ctx context.Context, conf *armour.Config) error {

	GlobalArmour = armour.NewArmour(ctx, conf)
	err := GlobalArmour.Init()
	if err != nil {
		GlobalArmour = nil
		return err
	}

	runnerWorkerPID, err := getRunnerWorkerPID()
	if err != nil {
		WriteLog(fmt.Sprintf("[armour] Error getting Runner.Worker PID: %v", err))
		return nil
	}
	GlobalArmour.SetRunnerWorkerPID(runnerWorkerPID)
	WriteLog(fmt.Sprintf("[armour] Runner.Worker PID: %d", runnerWorkerPID))

	return nil
}
