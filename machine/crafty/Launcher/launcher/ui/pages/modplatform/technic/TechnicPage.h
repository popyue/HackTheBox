/* Copyright 2013-2021 MultiMC Contributors
 * Copyright 2021-2022 Jamie Mansfield <jmansfield@cadixdev.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <QWidget>

#include "ui/pages/BasePage.h"
#include <Application.h>
#include "net/NetJob.h"
#include "tasks/Task.h"
#include "TechnicData.h"

namespace Ui
{
class TechnicPage;
}

class NewInstanceDialog;

namespace Technic {
    class ListModel;
}

class TechnicPage : public QWidget, public BasePage
{
    Q_OBJECT

public:
    explicit TechnicPage(NewInstanceDialog* dialog, QWidget *parent = 0);
    virtual ~TechnicPage();
    virtual QString displayName() const override
    {
        return tr("Technic");
    }
    virtual QIcon icon() const override
    {
        return APPLICATION->getThemedIcon("technic");
    }
    virtual QString id() const override
    {
        return "technic";
    }
    virtual QString helpPage() const override
    {
        return "Technic-platform";
    }
    virtual bool shouldDisplay() const override;

    void openedImpl() override;

    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void suggestCurrent();
    void metadataLoaded();
    void selectVersion();

private slots:
    void triggerSearch();
    void onSelectionChanged(QModelIndex first, QModelIndex second);
    void onSolderLoaded();
    void onVersionSelectionChanged(QString data);

private:
    Ui::TechnicPage *ui = nullptr;
    NewInstanceDialog* dialog = nullptr;
    Technic::ListModel* model = nullptr;

    Technic::Modpack current;
    QString selectedVersion;

    NetJob::Ptr jobPtr;
    QByteArray response;
};
