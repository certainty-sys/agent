package logger

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type FormatterHook struct {
	Writer    io.Writer
	LogLevels []logrus.Level
	Formatter logrus.Formatter
}

type reFormatter struct {
	logrus.TextFormatter
}

func (hook *FormatterHook) Fire(entry *logrus.Entry) error {
	line, err := hook.Formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = hook.Writer.Write(line)
	return err
}

func (hook *FormatterHook) Levels() []logrus.Level {
	return hook.LogLevels
}

func (f *reFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		levelColor = 31 // gray
	case logrus.WarnLevel:
		levelColor = 33 // yellow
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = 31 // red
	default:
		levelColor = 36 // blue
	}

	var levelText = fmt.Sprintf("\x1b[%dm%s\x1b[0m", levelColor, strings.ToUpper(entry.Level.String()))
	if f.DisableColors {
		levelText = strings.ToUpper(entry.Level.String())
	}

	return []byte(fmt.Sprintf("%s [%s] %s:%d: %s", entry.Time.Format(f.TimestampFormat), levelText, formatFilePath(entry.Caller.File), entry.Caller.Line, entry.Message)), nil
}

func init() {
	logrus.SetReportCaller(true)
	formatter := &reFormatter{logrus.TextFormatter{
		TimestampFormat:        "2006-01-02 15:04:05 MST",
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	}}
	logrus.SetFormatter(formatter)

	logFile, err := os.OpenFile("agent.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		logrus.Errorf("Error opening file for logging: %v", err)
	}

	logrus.AddHook(&FormatterHook{
		Writer: logFile,
		LogLevels: []logrus.Level{
			logrus.DebugLevel,
			logrus.InfoLevel,
			logrus.WarnLevel,
			logrus.ErrorLevel,
			logrus.FatalLevel,
			logrus.PanicLevel,
		},
		Formatter: &reFormatter{logrus.TextFormatter{
			TimestampFormat:        "2006-01-02 15:04:05 MST",
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			DisableColors:          true,
		}},
	})
}

func formatFilePath(path string) string {
	arr := strings.Split(path, "/")
	return arr[len(arr)-1]
}
