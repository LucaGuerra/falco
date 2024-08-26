// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <gtest/gtest.h>
#include <falco/configuration.h>

TEST(ConfigurationRuleOutputOptions, parse_yaml)
{
	falco_configuration falco_config;
	ASSERT_NO_THROW(falco_config.init_from_content(R"(
append_output:
  - source: syscall
    tag: persistence
    rule: some rule name
    format: "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"

  - tag: persistence
    fields:
      - proc.aname[2]: "%proc.aname[2]"
      - proc.aname[3]: "%proc.aname[3]"
      - proc.aname[4]: "%proc.aname[4]"
    format: "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"

  - source: k8s_audit
    fields:
      - ka.verb
      - static_field: "static content"

	)", {}));

	EXPECT_EQ(falco_config.m_append_output.size(), 3);

	EXPECT_EQ(falco_config.m_append_output[0].m_source, "syscall");
	EXPECT_EQ(falco_config.m_append_output[0].m_tag, "persistence");
	EXPECT_EQ(falco_config.m_append_output[0].m_rule, "some rule name");
	EXPECT_EQ(falco_config.m_append_output[0].m_formatted_fields.size(), 0);
	EXPECT_EQ(falco_config.m_append_output[0].m_format, "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_tag, "persistence");
	EXPECT_EQ(falco_config.m_append_output[1].m_format, "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields.size(), 3);
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[2]"], "%proc.aname[2]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[3]"], "%proc.aname[3]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[4]"], "%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[2].m_source, "k8s_audit");

	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields["static_field"], "static content");

	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.count("ka.verb"), 1);
}
